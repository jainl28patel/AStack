# AStack
- TCP/UDP network stack implemented above Data link layer using linux RAW sockets.
- Goal is to expose same API as provided by the transport layer with same data format but faster.

## Progress
- UDP : Done
- TCP : three-way-handshake for connect and disconnect, make packet utility and send packets functions are done.

## Left
- TCP : Handling states and adding Finite state machine(FSM) in TCP class.
- TCP: Implement `listen()` and `accept()` (basically PASSIVE sockets).
