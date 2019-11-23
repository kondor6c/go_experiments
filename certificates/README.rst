Goals:
- An all in one binary to work with certificates (hence the current "heredoc" like variables in var-data.go)
- Use only the standard library, no magic packages/modules


The web interface should be very simple to use and not expose many complexities of x509 certificates. But it should also be strict and not allow for misconfigurations or other mistakes.

Update:
There has been a longer period of dormancy on this project due to the fact that I examined Cloudflare's project cfssl. After realizing that much of what I had been trying to accomplish had already been done years prior I shoved this away, slightly disheartened. But I looked at it more and realized that there are some parts that I don't care for, and that I could benefit by continuing in writing this since I'll get better at programming and create something neat. Additionally peers commentedt that cert-manager for Kubernetes has some parallels too. But I think that has a more narrow focus. Besides some slight overlap by both projects, I'll continue on and plan for the ability to consume their data structure as well as the data schema I have created. That new structure combines some parts of both, projects, I used some of the type structs from cfssl (also the test data to reliably test against same conditions) and the "issuerRef" from cert-manager in the requests. 
Something I didn't see was the ability to "clone" a certificate, which had really been a large part of why I created this. Newer releases of Openssl have this, but I wanted to be able to pull from a remote location or upload a certificate and create a new CSR based off the source. We could then sign it where ever, eventually from here with a alias/CA set. From my observations many technicians or managers just want the same thing that is currently out there, since it's "working". 
I also still want the ability to handle Java KeyStores
