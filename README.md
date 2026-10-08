# metamask-wallet-recovery

I wrote this after finding an old MetaMask vault file on a backup drive and
forgetting the password. It extracts the encrypted vault from browser extension
storage and runs scrypt + AES-GCM decryption against your password list.

## install

pip install -r requirements.txt

## usage

Keep your password list tight. scrypt is slow by design.

<!-- last-checked: 2026-10-08 -->
