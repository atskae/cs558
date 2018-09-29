Atsuko Shimizu
ashimiz1@binghamton.edu

Tested on remote.cs

--

To build the program, run:
make

To run rc6, run:
./rc6 <input.txt> <output.txt>

Where <input.txt> is in the following format:
<action>
<message type>: <message>
<user key>

--

<action> is either the string "Encryption" or "Decryption"
<message type> is either the string "plaintext" or "ciphertext"
<message> is the plaintext or ciphertext in byte-format
<user-key> is the user-key in byte-format

--

Notes
- The program implements the RC6 algorithm, specifically RC6-32-20-b (32-bit words, 20 rounds), which either encrypts or decrypts a given message with a user-supplied key.
- The input text format is important... I use the ':' to know when the message and user-key starts when parsing the input file, so please do not forget the ':'.
- The program might hang if the input format is not correct.
