// nano-ble-bridge: carries the Xbox Nano's companion protocol between a Unix
// socket and its GATT channel (service 00000000-16e2-…, characteristic
// 00000004-16e2-…, writes and indications). Socket messages are
// <u16 little-endian length><frame>. A zero-length message to the client
// means "ready". Runs as an app so it gets its own Bluetooth permission.
import Foundation
import CoreBluetooth

let args = CommandLine.arguments
guard args.count >= 2 else { exit(2) }
let socketPath = args[1]
let logPath = args.count > 2 ? args[2] : nil
let logHandle: FileHandle? = logPath.flatMap { FileManager.default.createFile(atPath: $0, contents: nil); return FileHandle(forWritingAtPath: $0) }
func log(_ s: String) { logHandle?.write((s + "\n").data(using: .utf8)!) }
let serviceUUID = CBUUID(string: "00000000-16E2-469D-8013-A85CCD1A3F11")
let channelUUID = CBUUID(string: "00000004-16E2-469D-8013-A85CCD1A3F11")

var client: Int32 = -1
func sendToClient(_ data: Data) {
    guard client >= 0 else { return }
    var header = [UInt8(data.count & 0xff), UInt8(data.count >> 8)]
    _ = header.withUnsafeMutableBytes { write(client, $0.baseAddress, 2) }
    if !data.isEmpty { _ = data.withUnsafeBytes { write(client, $0.baseAddress, data.count) } }
}

final class Bridge: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    var central: CBCentralManager!
    var peripheral: CBPeripheral?
    var channel: CBCharacteristic?
    var ready = false
    override init() { super.init(); central = CBCentralManager(delegate: self, queue: nil) }
    func centralManagerDidUpdateState(_ c: CBCentralManager) {
        guard c.state == .poweredOn else { log("bluetooth state \(c.state.rawValue)"); if c.state != .unknown && c.state != .resetting { exit(3) }; return }
        guard let p = c.retrieveConnectedPeripherals(withServices: [serviceUUID]).first else { log("no connected Nano"); exit(4) }
        peripheral = p; p.delegate = self; c.connect(p)
    }
    func centralManager(_ c: CBCentralManager, didConnect p: CBPeripheral) { p.discoverServices([serviceUUID]) }
    func centralManager(_ c: CBCentralManager, didDisconnectPeripheral p: CBPeripheral, error: Error?) { log("disconnected \(String(describing: error))"); exit(5) }
    func peripheral(_ p: CBPeripheral, didDiscoverServices error: Error?) {
        guard let s = p.services?.first(where: { $0.uuid == serviceUUID }) else { log("no service"); exit(4) }
        p.discoverCharacteristics([channelUUID], for: s)
    }
    func peripheral(_ p: CBPeripheral, didDiscoverCharacteristicsFor s: CBService, error: Error?) {
        guard let c = s.characteristics?.first(where: { $0.uuid == channelUUID }) else { log("no channel"); exit(4) }
        channel = c; p.setNotifyValue(true, for: c)
    }
    func peripheral(_ p: CBPeripheral, didUpdateNotificationStateFor c: CBCharacteristic, error: Error?) {
        guard c.isNotifying else { log("notify failed \(String(describing: error))"); exit(4) }
        ready = true; log("ready")
        sendToClient(Data())
    }
    func peripheral(_ p: CBPeripheral, didUpdateValueFor c: CBCharacteristic, error: Error?) {
        if let v = c.value { sendToClient(v) }
    }
    func peripheral(_ p: CBPeripheral, didWriteValueFor c: CBCharacteristic, error: Error?) {
        if let error { log("write error \(error)") }
    }
    func write(_ data: Data) {
        guard let p = peripheral, let c = channel else { return }
        p.writeValue(data, for: c, type: .withResponse)
    }
}

unlink(socketPath)
let server = socket(AF_UNIX, SOCK_STREAM, 0)
var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
_ = withUnsafeMutablePointer(to: &address.sun_path) { ptr in socketPath.withCString { strncpy(UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self), $0, 103) } }
let bound = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(server, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
guard bound == 0, listen(server, 1) == 0 else { log("socket failed \(errno)"); exit(6) }

let bridge = Bridge()
Thread.detachNewThread {
    let fd = accept(server, nil, nil)
    guard fd >= 0 else { exit(7) }
    DispatchQueue.main.sync { client = fd; if bridge.ready { sendToClient(Data()) } }
    var header = [UInt8](repeating: 0, count: 2)
    while true {
        if recv(fd, &header, 2, MSG_WAITALL) != 2 { break }
        let length = Int(header[0]) | Int(header[1]) << 8
        var body = [UInt8](repeating: 0, count: length)
        if length > 0 && recv(fd, &body, length, MSG_WAITALL) != length { break }
        let data = Data(body)
        DispatchQueue.main.async { bridge.write(data) }
    }
    log("client closed"); unlink(socketPath); exit(0)
}
DispatchQueue.main.asyncAfter(deadline: .now() + 600) { log("idle limit"); exit(0) }
RunLoop.main.run()
