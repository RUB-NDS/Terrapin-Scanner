# Terrapin Vulnerability Scanner

The Terrapin Vulnerability Scanner is a small utility program written in Go, which can be used to determine the vulnerability of an SSH client or server against the [Terrapin Attack](https://terrapin-attack.com). The vulnerability scanner requires a single connection with the peer to gather all supported algorithms. However, it does not perform a fully fledged SSH key exchange, will never attempt authentication on a server, and does not perform the attack in practice. Instead, vulnerability is determined by checking the supported algorithms and support for known countermeasures (strict key exchange). This may falsely claim vulnerability in case the peer supports countermeasures unknown to this tool.

## Running

For convenience, we are providing pre-compiled binaries for all major desktop platforms. These can be found on the [Release page](https://github.com/RUB-NDS/Terrapin-Scanner/releases/latest). We have also provided a Docker image that supports most of the major architectures. This image can be run as:

```bash
docker run --rm -it ghcr.io/rub-nds/terrapin-scanner <args>
```

> [!IMPORTANT]  
> Note that when running the Terrapin Vulnerability Scanner inside a Docker container, the tool will bind to the container's localhost when specifying `--listen` with port only. To avoid connectivity issues, add `0.0.0.0` as its bind address and map the container's port to the host via Docker's `-p` argument.
>
> The following command will make the Terrapin Vulnerability Scanner available at port 2222 on the host system's localhost:
> ```bash
> docker run --rm -it -p localhost:2222:2222 ghcr.io/rub-nds/terrapin-scanner --listen 0.0.0.0:2222
> ```

## Building

However, we understand that you might prefer building tools that connect to your SSH server yourself. To do this, ensure that you have at least Go v1.18 installed. To compile and install the Terrapin Vulnerability Scanner Go package, run the command below.

```bash
go install github.com/RUB-NDS/Terrapin-Scanner@latest
```

This will download, compile, and install the Go package for your local system. The compiled binary will become available at `$GOBIN/Terrapin-Scanner`. If the `GOBIN` environment variable is not set, Go will default to using `$GOPATH/bin` or `$HOME/go/bin`, depending on whether the `$GOPATH` environment variable is set.

You can also build the Docker image yourself by running the commands below.

```bash
git clone https://github.com/RUB-NDS/Terrapin-Scanner.git
docker build -t terrapin-scanner Terrapin-Scanner
```

## Usage

```bash
# Scan the SSH server available at localhost port 2222
./Terrapin-Scanner --connect localhost:2222

# If no port is specified, the tool will default to port 22 instead
./Terrapin-Scanner --connect localhost

# To scan an SSH client, specify the listen command instead
# After running the command, you will need to connect with your SSH client to port 2222
./Terrapin-Scanner --listen 0.0.0.0:2222

# When binding to localhost, you can omit the interface address
# The following command will listen for incoming connections on 127.0.0.1:2222
./Terrapin-Scanner --listen 2222
```

The scanner supports outputting the scan result as json. To do so, provide the `--json` flag when calling the scanner. The output is structured as follows:

```json
{
    "RemoteAddr": "127.0.0.1:22",
    "IsServer": true,
    "Banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.5",
    "SupportsChaCha20": true,
    "SupportsCbcEtm": false,
    "SupportsStrictKex": true,
    "Vulnerable": false
}
```
