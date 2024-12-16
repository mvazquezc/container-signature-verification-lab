# LAB - Container Signature Verification on OpenShift Disconnected

During these labs we will be using a mirror registry where we will host OpenShift Container Platfor images, as well as other user-created images.

The mirror registry we will be using is Quay. For this test we are using a non-production setup using `mirror-registry`, you can get yours configured following the [official docs](https://docs.redhat.com/en/documentation/openshift_container_platform/4.17/html/disconnected_environments/mirroring-in-disconnected-environments#mirror-registry-localhost_installing-mirroring-creating-registry).

We ran the deployment like this:

~~~sh
INIT_USER=<your_user>
INIT_PWD=<your_password>
HOST=<your_host>
SSH_KEY=~/.ssh/id_rsa

./mirror-registry install --initUser ${INIT_USER} --initPassword ${INIT_PWD} --targetHostname ${HOST} --quayHostname ${HOST} --ssh-key ${SSH_KEY} --sslCheckSkip true 
~~~

We also need a http server that will host gpg signatures. We have configured `httpd` in the same host where the registry runs, it's configured to listen on port `8080` (you can use whatever port you want).

## Verifying OpenShift Release Images

In a default configuration, the runtime doesn't verify image signatures. In this section we will see how to configure the runtime to verify container images signatures for images coming from `quay.io/openshift-release-dev`.

1. Deploy a disconnected cluster following the official docs.

2. Check the default configuration on any node:

    ~~~sh
    cat /etc/containers/policy.json 
    ~~~

    ~~~json
    {
        "default": [
            {
                "type": "insecureAcceptAnything"
            }
        ],
        "transports":
            {
                "docker-daemon":
                    {
                        "": [{"type":"insecureAcceptAnything"}]
                    }
            }
    }
    ~~~

    ~~~sh
    cat /etc/containers/registries.d/*redhat*.yaml
    ~~~

    ~~~sh
    docker:
         registry.access.redhat.com:
             sigstore: https://access.redhat.com/webassets/docker/content/sigstore
    docker:
         registry.redhat.io:
             sigstore: https://registry.redhat.io/containers/sigstore
    ~~~

3. GPG signatures for release images are published [here](https://mirror.openshift.com/pub/openshift-v4/signatures/).

4. We can get a signature for a release image in an automated way like this:

    ~~~sh
    DIGEST=$(oc adm release info 4.17.7 -o jsonpath='{.digest}' | awk -F ":" '{print $2}')
    curl -sL https://mirror.openshift.com/pub/openshift-v4/signatures/openshift-release-dev/ocp-release/sha256%3D${DIGEST}/signature-1 | gpg --decrypt
    ~~~

5. Component images are not signed, those are referenced by digest by the OCP Release Image. You can get the referenced images like this:

    ~~~sh
    oc adm release info 4.17.7 --pullspecs
    ~~~

## Signing our containers using GPG

1. Make sure required RPMs are installed:

    ~~~sh
    sudo dnf install podman skopeo xxd jq -y
    ~~~

2. Create our private gpg key:

    ~~~sh
    sudo gpg --gen-key
    ~~~

3. Verify key is installed:

    ~~~sh
    sudo gpg --list-keys mario@example.com
    ~~~

4. Create our test images:

    ~~~sh
    MIRROR_REGISTRY=my-registry.example.com:8443
    cat <<EOF > Dockerfile.gpg
    FROM quay.io/fedora/fedora-minimal:latest
    RUN echo "Hello World" > /tmp/hw.txt
    USER 1024
    CMD ["sleep", "infinity"]
    EOF
    sudo podman build -t ${MIRROR_REGISTRY}/mavazque/gpgtestsign:fedora -f Dockerfile.gpg
    ~~~

5. Login to the public registry and push image (generating signatures):

    ~~~sh
    sudo podman login ${MIRROR_REGISTRY}
    sudo podman push --sign-by mario@example.com ${MIRROR_REGISTRY}/mavazque/gpgtestsign:fedora
    ~~~

6. Check signatures:

    ~~~sh
    ls -l /var/lib/containers/sigstore/mavazque/
    gpg --decrypt /var/lib/containers/sigstore/mavazque/*/signature-1
    ~~~

7. Copy signatures to a webserver:

    ~~~sh
    scp -pr /var/lib/containers/sigstore/mavazque user@mywebserver:/path/to/webserver
    ~~~

## Signing our containers using Cosign

> **NOTE**: We will be using our own PKI for these tests. The labs create a self-signed CA to issue required certificates.

1. Generate self-signed CA and required certs.

    ~~~sh
    # Generate RootCA
    openssl req -x509 -newkey rsa:4096 -keyout root-ca-key.pem -sha256 -noenc -days 9999 -subj "/C=ES/L=Valencia/O=IT/OU=Security/CN=Example Root Certificate Authority" -out root-ca.pem
    # Generate Intermediate CA Request
    openssl req -noenc -newkey rsa:4096 -keyout intermediate-ca-key.pem -addext "subjectKeyIdentifier = hash" -addext "keyUsage = critical,keyCertSign" -addext "basicConstraints = critical,CA:TRUE,pathlen:2" -subj "/C=ES/L=Valencia/O=IT/OU=Security/CN=Example Intermediate Certificate Authority" -out intermediate-ca.csr
    # Issue Intermediate CA
    openssl x509 -req -days 9999 -sha256 -in intermediate-ca.csr -CA root-ca.pem -CAkey root-ca-key.pem -copy_extensions copy -out intermediate-ca.pem
    # Generate Team A and B signing certs (OID_1_1 is the hexadecimal representation of the oidcissuer url)
    OID_1_1=$(echo -n "https://example.com" | xxd -p -u)
    # Request Team A Certificate
    openssl req -noenc -newkey rsa:4096 -keyout team-a-key.pem -addext "subjectKeyIdentifier = hash" -addext "basicConstraints = critical,CA:FALSE" -addext "keyUsage = critical,digitalSignature" -addext "subjectAltName = email:team-a@example.com" -addext "1.3.6.1.4.1.57264.1.1 = DER:${OID_1_1}" -addext "1.3.6.1.4.1.57264.1.8 = ASN1:UTF8String:https://example.com" -subj "/C=ES/L=Valencia/O=IT/OU=Security/CN=Team A Cosign Certificate" -out team-a.csr
    # Issue Team A Certificate
    openssl x509 -req -in team-a.csr -CA intermediate-ca.pem -CAkey intermediate-ca-key.pem -copy_extensions copy -days 9999 -sha256 -out team-a.pem
    # Request Team B Certificate
    openssl req -noenc -newkey rsa:4096 -keyout team-b-key.pem -addext "subjectKeyIdentifier = hash" -addext "basicConstraints = critical,CA:FALSE" -addext "keyUsage = critical,digitalSignature" -addext "subjectAltName = email:team-b@example.com" -addext "1.3.6.1.4.1.57264.1.1 = DER:${OID_1_1}" -addext "1.3.6.1.4.1.57264.1.8 = ASN1:UTF8String:https://example.com" -subj "/C=ES/L=Valencia/O=IT/OU=Security/CN=Team B Cosign Certificate" -out team-b.csr
    # Issue Team B Certificate
    openssl x509 -req -in team-b.csr -CA intermediate-ca.pem -CAkey intermediate-ca-key.pem -copy_extensions copy -days 9999 -sha256 -out team-b.pem
    ~~~

2. Create our test image:

    ~~~sh
    MIRROR_REGISTRY=my-registry.example.com:8443
    cat <<'EOF' > Dockerfile.cosign
    FROM quay.io/fedora/fedora-minimal:latest
    ARG GREETING
    RUN echo $GREETING > /tmp/hw.txt
    USER 1024
    CMD ["sleep", "infinity"]
    EOF
    sudo podman build --build-arg GREETING="Hello from Team A" -t ${MIRROR_REGISTRY}/mavazque/cosigntestsign:team-a -f Dockerfile.cosign
    sudo podman build --build-arg GREETING="Hello from Team B" -t ${MIRROR_REGISTRY}/mavazque/cosigntestsign:team-b -f Dockerfile.cosign
    sudo podman push --digestfile image-digest-team-a ${MIRROR_REGISTRY}/mavazque/cosigntestsign:team-a
    sudo podman push --digestfile image-digest-team-b ${MIRROR_REGISTRY}/mavazque/cosigntestsign:team-b
    ~~~

3. Install cosign cli:

    ~~~sh
    sudo curl -L https://github.com/sigstore/cosign/releases/download/v2.2.4/cosign-linux-amd64 -o /usr/local/bin/cosign
    sudo chmod +x /usr/local/bin/cosign
    ~~~

4. Import Cosign certificates:

    ~~~sh
    cosign import-key-pair --key team-a-key.pem --output-key-prefix=import-team-a
    cosign import-key-pair --key team-b-key.pem --output-key-prefix=import-team-b
    ~~~

5. Build trust chain bundle:

    ~~~sh
    cat intermediate-ca.pem root-ca.pem > ca-bundle.pem
    ~~~

6. Sign Images:

    ~~~sh
    REGISTRY_USER=<your_user>
    REGISTRY_PWD=<your_password>
    TEAM_A_IMAGE_DIGEST=$(cat image-digest-team-a)
    TEAM_B_IMAGE_DIGEST=$(cat image-digest-team-b)
    cosign sign --registry-username ${REGISTRY_USER} --registry-password ${REGISTRY_PWD} --key import-team-a.key --tlog-upload=true --cert team-a.pem --cert-chain ca-bundle.pem --sign-container-identity ${MIRROR_REGISTRY}/mavazque/cosigntestsign:team-a ${MIRROR_REGISTRY}/mavazque/cosigntestsign@${TEAM_A_IMAGE_DIGEST}
    cosign sign --registry-username ${REGISTRY_USER} --registry-password ${REGISTRY_PWD} --key import-team-b.key --tlog-upload=true --cert team-b.pem --cert-chain ca-bundle.pem --sign-container-identity ${MIRROR_REGISTRY}/mavazque/cosigntestsign:team-b ${MIRROR_REGISTRY}/mavazque/cosigntestsign@${TEAM_B_IMAGE_DIGEST}
    ~~~

7. We can validate signatures with cosign cli:

    ~~~sh
    cosign verify --registry-username ${REGISTRY_USER} --registry-password ${REGISTRY_PWD} --certificate-identity='team-a@example.com' --certificate-oidc-issuer='https://example.com' --insecure-ignore-sct --insecure-ignore-tlog --cert-chain=root-ca.pem ${MIRROR_REGISTRY}/mavazque/cosigntestsign@${TEAM_A_IMAGE_DIGEST}
    cosign verify --registry-username ${REGISTRY_USER} --registry-password ${REGISTRY_PWD} --certificate-identity='team-b@example.com' --certificate-oidc-issuer='https://example.com' --insecure-ignore-sct --insecure-ignore-tlog --cert-chain=root-ca.pem ${MIRROR_REGISTRY}/mavazque/cosigntestsign@${TEAM_B_IMAGE_DIGEST}
    ~~~

8. We can check the signature from Skopeo and also in the Quay registry:

    ~~~sh
    SIGNATURE_TAG=$(echo ${TEAM_A_IMAGE_DIGEST} | sed "s/:/-/" | sed "s/$/.sig/")
    # Get certificate that signed the image
    sudo skopeo inspect docker://${MIRROR_REGISTRY}/mavazque/cosigntestsign:${SIGNATURE_TAG} | jq -r '.LayersData[].Annotations."dev.sigstore.cosign/certificate"' | sed 's/\\n/\n/g' | grep -v null | openssl x509 -text
    # Get trust chain for the certificate
    sudo skopeo inspect docker://${MIRROR_REGISTRY}/mavazque/cosigntestsign:${SIGNATURE_TAG} | jq -r '.LayersData[].Annotations."dev.sigstore.cosign/chain"' | sed 's/\\n/\n/g' | grep -v null
    # Get image signature
    sudo skopeo inspect docker://${MIRROR_REGISTRY}/mavazque/cosigntestsign:${SIGNATURE_TAG} | jq -r '.LayersData[].Annotations."dev.cosignproject.cosign/signature"'
    ~~~

## Configure image verification for OpenShift release images

### GPG Verification

1. Mirror GPG signature for the release we want to verify signatures for:

    > NOTE: The command below must be run in the webserver.

    ~~~sh
    WEB_SERVER_DOCROOT_DIR=/var/www/html
    DIGEST=$(oc adm release info 4.17.7 -o jsonpath='{.digest}' | awk -F ":" '{print $2}')
    
    mkdir -p ${WEB_SERVER_DOCROOT_DIR}/signatures/openshift-release-dev/ocp-release@sha256=${DIGEST}
    
    curl -sL https://mirror.openshift.com/pub/openshift-v4/signatures/openshift-release-dev/ocp-release/sha256%3D${DIGEST}/signature-1 -o ${WEB_SERVER_DOCROOT_DIR}/signatures/openshift-release-dev/ocp-release@sha256=${DIGEST}/signature-1
    ~~~

2. Configure the OpenShift cluster to verify container's image signature for images from `quay.io/openshift-release-dev/ocp-release`:

    > **NOTE**: We're running on a compact cluster, modify MachineConfig role as required in your config.

    ~~~sh
    MIRROR_REGISTRY=my-registry.example.com:8443
    WEB_SERVER=my-registry.example.com:8080

    # Generate Container Policy, this policy tells image ocp-release from the mirror registry or quay.io in the namespace openshift-release-dev to verify signatures using the public GPG key from Red Hat
    B64_POLICY=$(cat <<EOF | base64 -w0
    {
        "default": [
            {
                "type": "insecureAcceptAnything"
            }
        ],
        "transports": {
            "docker": {
                "${MIRROR_REGISTRY}/openshift-release-dev/ocp-release": [
                    {
                        "type": "signedBy",
                        "keyType": "GPGKeys",
                        "keyPath": "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"
                    }
                ],
                "quay.io/openshift-release-dev/ocp-release": [
                    {
                        "type": "signedBy",
                        "keyType": "GPGKeys",
                        "keyPath": "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"
                    }
                ]
            },
            "docker-daemon": {
                "": [
                    {
                        "type": "insecureAcceptAnything"
                    }
                ]
            }
        }
    }
    EOF
    )

    # Generate Registry Configurations that tells the runtime to go look signatures into our webserver for image ocp-release from the mirror registry or quay.io in the namespace openshift-release-dev
    B64_REG_SIGSTORE_MIRROR=$(cat <<EOF | base64 -w0
    docker:
         ${MIRROR_REGISTRY}/openshift-release-dev/ocp-release:
             sigstore: http://${WEB_SERVER}/signatures
    EOF
    )

    B64_REG_SIGSTORE_QUAY=$(cat <<EOF | base64 -w0
    docker:
         quay.io/openshift-release-dev/ocp-release:
             sigstore: http://${WEB_SERVER}/signatures
    EOF
    )

    # Add configs to nodes using a MachineConfig
    cat <<EOF | oc apply -f -
    apiVersion: machineconfiguration.openshift.io/v1
    kind: MachineConfig
    metadata:
      labels:
        machineconfiguration.openshift.io/role: master
      name: 99-master-container-policy-configuration
    spec:
      config:
        ignition:
          config: {}
          security:
            tls: {}
          timeouts: {}
          version: 3.1.0
        networkd: {}
        passwd: {}
        storage:
          files:
          - contents:
              source: data:text/plain;charset=utf-8;base64,${B64_POLICY}
            mode: 420
            overwrite: true
            path: /etc/containers/policy.json
          - contents:
              source: data:text/plain;charset=utf-8;base64,${B64_REG_SIGSTORE_MIRROR}
            mode: 420
            overwrite: true
            path: /etc/containers/registries.d/$(echo ${MIRROR_REGISTRY} | awk -F ":" '{print $1}').yaml
          - contents:
              source: data:text/plain;charset=utf-8;base64,${B64_REG_SIGSTORE_QUAY}
            mode: 420
            overwrite: true
            path: /etc/containers/registries.d/quay.io.yaml
      osImageURL: ""
    EOF

    # Add mirror config so release images are pulled from our mirror (this sould be already configured if you did a disconnected install)
    cat <<EOF | oc apply -f -
    apiVersion: config.openshift.io/v1 
    kind: ImageDigestMirrorSet 
    metadata:
      name: ocp-release-repo
    spec:
      imageDigestMirrors: 
      - mirrors:
        - ${MIRROR_REGISTRY}/openshift-release-dev/ocp-release
        source: quay.io/openshift-release-dev/ocp-release
    EOF
    ~~~

3. Validate configuration by connecting to one of the cluster nodes (running the release image like a pod doesn't make sense in this case), we will be running crictl pull which is what OpenShift does under the hood:

    ~~~sh
    # Using the pullspec from the signature works
    crictl pull quay.io/openshift-release-dev/ocp-release@sha256:e8680baf0b44dc55accfe08c4ad298d508d5a19a371bc4747c2f6a92225aa38f
    
    # Using the pullspec from our registry does not work
    crictl pull mirror-registry.e2e.bos.redhat.com:8443/openshift-release-dev/ocp-release@sha256:e8680baf0b44dc55accfe08c4ad298d508d5a19a371bc4747c2f6a92225aa38f
    ~~~

4. For solving above error we could do identity remapping, this is supported for GPG (but under consideration for sigstore):

    > NOTE: Even if we can configure identity remapping, you want to pull from the original pull spec and rely on the mirror configuration.

    ~~~sh
    B64_POLICY=$(cat <<EOF | base64 -w0
    {
        "default": [
            {
                "type": "insecureAcceptAnything"
            }
        ],
        "transports": {
            "docker": {
                "${MIRROR_REGISTRY}/openshift-release-dev/ocp-release": [
                    {
                        "type": "signedBy",
                        "keyType": "GPGKeys",
                        "keyPath": "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release",
                        "signedIdentity": {
                            "type": "remapIdentity",
                            "prefix": "${MIRROR_REGISTRY}/openshift-release-dev/ocp-release",
                            "signedPrefix": "quay.io/openshift-release-dev/ocp-release"
                        }
                    }
                ],
                "quay.io/openshift-release-dev/ocp-release": [
                    {
                        "type": "signedBy",
                        "keyType": "GPGKeys",
                        "keyPath": "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"
                    }
                ]
            },
            "docker-daemon": {
                "": [
                    {
                        "type": "insecureAcceptAnything"
                    }
                ]
            }
        }
    }
    EOF
    )

    cat <<EOF | oc apply -f -
    apiVersion: machineconfiguration.openshift.io/v1
    kind: MachineConfig
    metadata:
      labels:
        machineconfiguration.openshift.io/role: master
      name: 99-master-container-policy-configuration
    spec:
      config:
        ignition:
          config: {}
          security:
            tls: {}
          timeouts: {}
          version: 3.1.0
        networkd: {}
        passwd: {}
        storage:
          files:
          - contents:
              source: data:text/plain;charset=utf-8;base64,${B64_POLICY}
            mode: 420
            overwrite: true
            path: /etc/containers/policy.json
          - contents:
              source: data:text/plain;charset=utf-8;base64,${B64_REG_SIGSTORE_MIRROR}
            mode: 420
            overwrite: true
            path: /etc/containers/registries.d/$(echo ${MIRROR_REGISTRY} | awk -F ":" '{print $1}').yaml
          - contents:
              source: data:text/plain;charset=utf-8;base64,${B64_REG_SIGSTORE_QUAY}
            mode: 420
            overwrite: true
            path: /etc/containers/registries.d/quay.io.yaml
      osImageURL: ""
    EOF
    ~~~

5. Pulling from our mirror directly works now:

    ~~~sh
    crictl pull mirror-registry.e2e.bos.redhat.com:8443/openshift-release-dev/ocp-release@sha256:e8680baf0b44dc55accfe08c4ad298d508d5a19a371bc4747c2f6a92225aa38f
    ~~~

6. Pulling using the tag works as well:

    ~~~sh
    crictl pull quay.io/openshift-release-dev/ocp-release:4.17.7-x86_64
    crictl pull mirror-registry.e2e.bos.redhat.com:8443/openshift-release-dev/ocp-release:4.17.7-x86_64
    ~~~

7. If we try to pull an image that we haven't mirrored the signatures for, it will fail:

    ~~~sh
    crictl pull quay.io/openshift-release-dev/ocp-release:4.17.6-x86_64
    ~~~

### Cosign Verification

N/A

## Configure image verification for our container images

### GPG Verification

1. Export public gpg key:

    ~~~sh
    B64_GPGKEY=$(sudo gpg --armor --export mario@example.com | base64 -w0)
    ~~~

2. Load our public gpg key in the node and modify the runtime config:

    > **NOTE**: We're running on a compact cluster, modify MachineConfig role as required in your config.

    ~~~sh
    # Generate Container Policy, this policy tells the runtime to verify container image signatures for images in the namespace mavazque from our registry using our gpg key
    B64_POLICY=$(cat <<EOF | base64 -w0
    {
        "default": [
            {
                "type": "insecureAcceptAnything"
            }
        ],
        "transports": {
            "docker": {
                "${MIRROR_REGISTRY}/openshift-release-dev/ocp-release": [
                    {
                        "type": "signedBy",
                        "keyType": "GPGKeys",
                        "keyPath": "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release",
                        "signedIdentity": {
                            "type": "remapIdentity",
                            "prefix": "${MIRROR_REGISTRY}/openshift-release-dev/ocp-release",
                            "signedPrefix": "quay.io/openshift-release-dev/ocp-release"
                        }
                    }
                ],
                "${MIRROR_REGISTRY}/mavazque": [
                    {
                        "type": "signedBy",
                        "keyType": "GPGKeys",
                        "keyPath": "/etc/pki/rpm-gpg/RPM-GPG-KEY-mario-example"
                    }
                ],
                "quay.io/openshift-release-dev/ocp-release": [
                    {
                        "type": "signedBy",
                        "keyType": "GPGKeys",
                        "keyPath": "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"
                    }
                ]
            },
            "docker-daemon": {
                "": [
                    {
                        "type": "insecureAcceptAnything"
                    }
                ]
            }
        }
    }
    EOF
    )

    # Generate Registry Configurations that tells the runtime to go look signatures into our webserver for images in the namespace mavazque from the mirror registry 
    B64_REG_SIGSTORE_MIRROR=$(cat <<EOF | base64 -w0
    docker:
        ${MIRROR_REGISTRY}/openshift-release-dev/ocp-release:
            sigstore: http://${WEB_SERVER}/signatures
        ${MIRROR_REGISTRY}/mavazque:
            sigstore: http://${WEB_SERVER}/signatures
    EOF
    )

    cat <<EOF | oc apply -f -
    apiVersion: machineconfiguration.openshift.io/v1
    kind: MachineConfig
    metadata:
      labels:
        machineconfiguration.openshift.io/role: master
      name: 99-master-container-policy-configuration
    spec:
      config:
        ignition:
          config: {}
          security:
            tls: {}
          timeouts: {}
          version: 3.1.0
        networkd: {}
        passwd: {}
        storage:
          files:
          - contents:
              source: data:text/plain;charset=utf-8;base64,${B64_POLICY}
            mode: 420
            overwrite: true
            path: /etc/containers/policy.json
          - contents:
              source: data:text/plain;charset=utf-8;base64,${B64_REG_SIGSTORE_MIRROR}
            mode: 420
            overwrite: true
            path: /etc/containers/registries.d/$(echo ${MIRROR_REGISTRY} | awk -F ":" '{print $1}').yaml
          - contents:
              source: data:text/plain;charset=utf-8;base64,${B64_REG_SIGSTORE_QUAY}
            mode: 420
            overwrite: true
            path: /etc/containers/registries.d/quay.io.yaml
          - contents:
              source: data:text/plain;charset=utf-8;base64,${B64_GPGKEY}
            mode: 420
            overwrite: true
            path: /etc/pki/rpm-gpg/RPM-GPG-KEY-mario-example
      osImageURL: ""
    EOF
    ~~~

3. Let's run two workloads, one is signed, the other is not:

    ~~~sh
    cat <<EOF | oc apply -f -
    ---
    apiVersion: v1
    kind: Namespace
    metadata:
      name: test-signature
    ---
    apiVersion: v1
    kind: Pod
    metadata:
      labels:
        run: signed-image-pod
      name: signed-image-pod
      namespace: test-signature
    spec:
      containers:
      - image: mirror-registry.e2e.bos.redhat.com:8443/mavazque/gpgtestsign:fedora
        name: signed-image-pod
        resources: {}
      dnsPolicy: ClusterFirst
      restartPolicy: Always
    ---
    apiVersion: v1
    kind: Pod
    metadata:
      labels:
        run: unsigned-image-pod
      name: unsigned-image-pod
      namespace: test-signature
    spec:
      containers:
      - image: mirror-registry.e2e.bos.redhat.com:8443/mavazque/reversewords:latest
        name: unsigned-image-pod
        resources: {}
      dnsPolicy: ClusterFirst
      restartPolicy: Always
    EOF
    ~~~

4. If we check pods:

    ~~~sh
    oc -n test-signature get pods
    ~~~

    ~~~console
    NAME                 READY   STATUS             RESTARTS      AGE
    signed-image-pod     0/1     Completed          2 (18s ago)   25s
    unsigned-image-pod   0/1     ImagePullBackOff   0             25s
    ~~~

    ~~~sh
    oc -n test-signature describe pod unsigned-image-pod
    ~~~

    ~~~console
    Warning  Failed          19s (x3 over 57s)  kubelet            Failed to pull image "mirror-registry.example.com:8443/mavazque/reversewords:latest": SignatureValidationFailed: copying system image from manifest list: Source image rejected: A signature was required, but no signature exists
    ~~~

### Cosign Verification

1. Configure root ca pem key

    ~~~sh
    B64_ROOTCA=$(cat root-ca.pem | base64 -w0)
    ~~~

2. Configure the OpenShift cluster to verify container images signature for images from `quay.io/mavazque/cosigntestsign` with sigstore:

    ~~~sh
    B64_POLICY=$(cat <<EOF | base64 -w0
    {
        "default": [
            {
                "type": "insecureAcceptAnything"
            }
        ],
        "transports": {
            "docker": {
                "${MIRROR_REGISTRY}/openshift-release-dev/ocp-release": [
                    {
                        "type": "signedBy",
                        "keyType": "GPGKeys",
                        "keyPath": "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release",
                        "signedIdentity": {
                            "type": "remapIdentity",
                            "prefix": "${MIRROR_REGISTRY}/openshift-release-dev/ocp-release",
                            "signedPrefix": "quay.io/openshift-release-dev/ocp-release"
                        }
                    }
                ],
                "${MIRROR_REGISTRY}/mavazque": [
                    {
                        "type": "signedBy",
                        "keyType": "GPGKeys",
                        "keyPath": "/etc/pki/rpm-gpg/RPM-GPG-KEY-mario-example"
                    }
                ],
                "${MIRROR_REGISTRY}/mavazque/cosigntestsign": [
                    {
                        "type": "sigstoreSigned",
                        "fulcio": {
                            "caPath": "/etc/containers/rootca-sig.pem",
                            "subjectEmail": "team-a@example.com",
                            "oidcIssuer": "https://example.com"
                        },
                        "rekorPublicKeyData": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFMkcyWSsydGFiZFRWNUJjR2lCSXgwYTlmQUZ3cgprQmJtTFNHdGtzNEwzcVg2eVlZMHp1ZkJuaEM4VXIvaXk1NUdoV1AvOUEvYlkyTGhDMzBNOStSWXR3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==",
                        "signedIdentity": { "type": "matchRepository" }
                    }
                ],
                "quay.io/openshift-release-dev/ocp-release": [
                    {
                        "type": "signedBy",
                        "keyType": "GPGKeys",
                        "keyPath": "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"
                    }
                ]
            },
            "docker-daemon": {
                "": [
                    {
                        "type": "insecureAcceptAnything"
                    }
                ]
            }
        }
    }
    EOF
    )

    B64_REG_SIGSTORE_MIRROR=$(cat <<EOF | base64 -w0
    docker:
        ${MIRROR_REGISTRY}/openshift-release-dev/ocp-release:
            sigstore: http://${WEB_SERVER}/signatures
        ${MIRROR_REGISTRY}/mavazque:
            sigstore: http://${WEB_SERVER}/signatures
        ${MIRROR_REGISTRY}/mavazque/cosigntestsign:
            use-sigstore-attachments: true
    EOF
    )
    ~~~

3. Update config

    ~~~sh
    cat <<EOF | oc apply -f -
    apiVersion: machineconfiguration.openshift.io/v1
    kind: MachineConfig
    metadata:
      labels:
        machineconfiguration.openshift.io/role: master
      name: 99-master-container-policy-configuration
    spec:
      config:
        ignition:
          config: {}
          security:
            tls: {}
          timeouts: {}
          version: 3.1.0
        networkd: {}
        passwd: {}
        storage:
          files:
          - contents:
              source: data:text/plain;charset=utf-8;base64,${B64_POLICY}
            mode: 420
            overwrite: true
            path: /etc/containers/policy.json
          - contents:
              source: data:text/plain;charset=utf-8;base64,${B64_REG_SIGSTORE_MIRROR}
            mode: 420
            overwrite: true
            path: /etc/containers/registries.d/$(echo ${MIRROR_REGISTRY} | awk -F ":" '{print $1}').yaml
          - contents:
              source: data:text/plain;charset=utf-8;base64,${B64_REG_SIGSTORE_QUAY}
            mode: 420
            overwrite: true
            path: /etc/containers/registries.d/quay.io.yaml
          - contents:
              source: data:text/plain;charset=utf-8;base64,${B64_GPGKEY}
            mode: 420
            overwrite: true
            path: /etc/pki/rpm-gpg/RPM-GPG-KEY-mario-example
          - contents:
              source: data:text/plain;charset=utf-8;base64,${B64_ROOTCA}
            mode: 420
            overwrite: true
            path: /etc/containers/rootca-sig.pem
      osImageURL: ""
    EOF
    ~~~

4. Let's run two workloads, one is signed, the other is not:

    ~~~sh
    cat <<EOF | oc apply -f -
    apiVersion: v1
    kind: Pod
    metadata:
      labels:
        run: cosign-signed-image-team-a
      name: cosign-signed-image-team-a
      namespace: test-signature
    spec:
      containers:
      - image: mirror-registry.e2e.bos.redhat.com:8443/mavazque/cosigntestsign:team-a
        name: cosign-signed-image-team-a
        resources: {}
      dnsPolicy: ClusterFirst
      restartPolicy: Always
    ---
    apiVersion: v1
    kind: Pod
    metadata:
      labels:
        run: cosign-signed-image-team-b
      name: cosign-signed-image-team-b
      namespace: test-signature
    spec:
      containers:
      - image: mirror-registry.e2e.bos.redhat.com:8443/mavazque/cosigntestsign:team-b
        name: cosign-signed-image-team-b
        resources: {}
      dnsPolicy: ClusterFirst
      restartPolicy: Always
    EOF
    ~~~

5. If we check pods:

    ~~~sh
    oc -n test-signature get pods
    ~~~

    ~~~console
    oc -n test-signature get pods
    NAME                         READY   STATUS                      RESTARTS   AGE
    cosign-signed-image-team-a   1/1     Running                     0          11s
    cosign-signed-image-team-b   0/1     SignatureValidationFailed   0          11s
    ~~~

    ~~~sh
    oc -n test-signature describe pod cosign-signed-image-team-b
    ~~~

    > NOTE: Signature validation failed because in the policy we configured `subjectEmail: team-a@example.com` and this image was signed by `team-b@example.com`. This is expected. Usually different teams use different repos.

    ~~~console
      Warning  Failed          22s (x2 over 39s)  kubelet            Failed to pull image "mirror-registry.example.com:8443/mavazque/cosigntestsign:team-b": SignatureValidationFailed: Source image rejected: None of the signatures were accepted, reasons: missing dev.sigstore.cosign/bundle annotation; Required email team-a@example.com not found (got []string{"team-b@example.com"})
    ~~~

## Cleanup

~~~sh
oc delete ns test-signature
oc delete mc 99-master-container-policy-configuration
~~~