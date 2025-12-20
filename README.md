

# BlockChain IDS Audit Trail
  Blockchain-Based Intrusion Detection System (IDS) Audit Trail to securely store and protect intrusion logs.
  
  ## Overview
  Traditional log files offer no built-in protection against tampering, making forensic investigations unreliable and reducing trust in the security monitoring process.

  Therefore, there is a need for a secure, tamper-resistant method of recording IDS alerts that remains trustworthy even if the underlying system is compromised. Therefore, there is a need for a secure, tamper-resistant method of recording IDS alerts that remains trustworthy even if the underlying system is compromised.

  ## Feature
   - Secure log storage using cryptographic hashing
   - Blockchain-based audit trail
   - Log integrity vrification activities
   - Alert generation for suspicious activities
   - Simple and modular architecture

  ## Technologies USed
  - Programming language: Python
  - Cryptography:HMAC,AES,SHA-256
  - Blockchain: Custom lightweight blockchain
  - Networking: Socket programming
  - Tools: Git,VS Code

  ## Installation
  - git clone https://github.com/Cheat123-CH/BloackChain_IDS
  - cd Blockchain_IDS
  - Install all required packages
      - pip install requests
      - pip install cryptography
      - pip install pycrytodome
    

  ## Usage
  Open separate terminals for each component and run the following commands in order:

  - Start Blockchain Nodes
      - python node.py --port 9000
      - python node.py --port 9001
  - Start Gateway
      - python gateway.py
  - Sensor Generate Log
      - python sensor.py sensor-1
      - python sensor.py sensor-2
  - Decrypt nodelog.txt.enc
      - python --decrypt-log
      - AES key: suppersecrete

  ## Sysetm Architecture
   - Sensors generate security logs
   - Gateway authenticates log
   - Logs are encrypted and sent to blockchain nodes
   - Blockchain ensures inmmutability and integrity
   - Encryption file for ensures confidentiality

  ## Cryptographic
   - HMAC for message authentication
   - SHA-256 for hashing blocks
   - AES for lgo encryption
        
  ## Project Structure
 ``` .
      ├── node.py
      ├── gateway.py
      ├── sensor.py
      ├── chain.json
      ├── IDSlog.py
      ├── nodelog.txt.enc
      └── README.md  
 ```

  ## Output / Results
      - Audit tail on gateway
      - Encrypted logs stored securely
      - Tamper detection through hash verification
  ## Testing
      - Node online / offline secenarios
      - Trust sensensor (sensor-1/sensor-2) / untrust sensors 
      - Log tampering simulation
      - Hashing mismatch detection
      - Compare chain.json and nodelog.txt(decrypt nodelog.txt.enc with AES key: suppersecret)
  ## Future Iprovements
      - Samrt Contract integration
      - web-based dashboard
      - database storage log
      - automate verification and detect tamper
      - Machine Learning-based anomaly detection
      - The system could be integrated with real IDS platforms such as Snort, Suricata, or Zeek

  ## Author
    Met Sokcheat:https://github.com/Cheat123-CH
 


 
    