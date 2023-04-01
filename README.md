# A-system-that-allows-passwords-to-be-securely-recorded
- The system is built on Model Client-Server: a server to store passwords and a client program to control passwords
(client)
- Reliance on Sockets according to IP/TCP connection
- Dependence on the server on Threading-Multi or Driven-Event (that is, it is possible to serve more than one client at the same time).

The project supports information security, especially in the following aspects:
1- Make sure that the person or server with whom you are communicating is really the person you want to communicate with .
2- Confidentiality
3- Integrity of information
4- Non-Repudiation
5- Authentication
6- End-to-End Encryption

- Requests and responses are encrypted in the network by AES and RSA
- The server or user does not accept any request or response without a proper MAC
- The user can modify only his passwords (Authorization).
- Handshaking takes place between the server and the client at each session
- Maintain confidentiality of information using Hybrid encryption PGP .
- Use a digital signature .
- Using Digital Certificates and using Authority Certificates .
- When creating a new user, the client program generates private-public keys for the client and saves its keys for RSA encryption.
