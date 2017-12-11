# HIOcontainer

Building containers for Harmonic IO. Build the container from the HIOContainer folder with: 

docker build -t "name" .



# To Run

Review: suggestion, use a bindmount to get the JSON config file mapped into the container with the passwords.
See: https://www.digitalocean.com/community/tutorials/how-to-share-data-between-the-docker-container-and-the-host#step-2-—-accessing-data-on-the-host

Example JSON config is here:
https://github.com/benblamey/HasteStorageClient/blob/master/config/haste_storage_client_config.json

Add an example config.json to this repo
Add example to this readme to run the container with the mapping setup (the -v args)
Then, add the config needed for the HASTE production environment in SNIC, and use gitcrypt to encrypt it:
https://github.com/AGWA/git-crypt  (we should have a HASTE gitcrpyt key)

This approach means:
- You can still publish your container without leaking passwords (the config file won't be in the container)
- You can still open-source your other code without leaking the passwords
- We won't need to faff about with an extra server (which will require its own access mechanism anyway)
- We can keep everything in source control
