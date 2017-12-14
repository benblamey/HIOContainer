# HIOcontainer

## Building

Building containers for Harmonic IO. Build the container from the HIOContainer folder with: 

```
docker build -t "hio-image-analysis" .
```

## Running

Unlock git-crypt:

```
git crypt unlock ~/haste-git-crypt-key
```

Run the container with (e.g on MacOS):

```
docker run -v /Users/<username>/projects/haste/HIOContainer/enc/haste_storage_client_config.json:/haste_storage_client_config.json "hio-image-analysis"
```