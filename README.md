# Socket-based-AES-key-exchange




This project has 2 parts. A client and a server. Client is Android. Server is a basic Java server; socket-supporting  and just does the job.

I tried to implement an unsual way of exchanging AES (symmetric) keys. What I am effectively doing is once public keys are exchanged, public keys will be used to encrypt AES keys and then sent over (an unsecure channel). Post this exchange, the job of RSA algorithm is done and from that point in time, one should use AES keys for further exchange or communication, of whatsover type.


Following is the process of exchange:
- Client sends his locally generated RSA public key, as a string, to Server.
- Server sends his locally generated RSA public key, as a string, to Client.
- Since the received public keys are actually received as strings, they have to realised back as public keys for any usage. This is possible using the components of that string, i.e., public key's modulus and exponent. It is being done on both sides.
- Once this is done, both the parties will move ahead with the encryption and forwarding of encrypted AES keys. Note that we are just interacting with the Android-type client. Server is going to be responding in a specific manner to the communication being done.
