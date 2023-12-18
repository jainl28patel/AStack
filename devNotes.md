# Notes

## TCP
- handshake mechanism with clock-based sequence numbers.
- The purpose of push function and the PUSH flag is to push data through from the sending user to the receiving user.  It does not provide a record service.
- If the receiving TCP is in a  non-synchronized state (i.e., SYN-SENT, SYN-RECEIVED), it returns to LISTEN on receiving an acceptable reset. If the TCP is in one of the synchronized states (ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT), it aborts the connection and informs its user.