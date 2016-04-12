localca
=======

Package localca is a simple solution for using https or http2 in your local area network with go.

You need certificates. At least if you want to play with http2 or don't own or trust your wifi-router with your local web traffic.

But using certificates for devices in local networks has some problems:

 * Generating, installing and managing certificates for multiple devices is not fun.
 * There are many ways to talk to your device but only those listed in the certificate are accepted by browsers.
 * With DHCP your local devices may change IPs.

With localca you can create a server that:
 * serves a PEM encoded CA certificate on http, users need to import it only once into the browser certificates.
 * automatically self-signs server certificates including the name or IP used to talk to the server.

Example
-------
	
	// read pem encoded key and ca certificate
	key, err := localca.ReadKey(keyPEM)
	if err != nil {
		log.Fatal(err)
	}
	ca, err := localca.Read(nil, key, caPEM)
	if err != nil {
		log.Fatal(err)
	}

	// start a http server on port 8080 that serves the ca certificate
	go http.ListenAndServe(":8080", ca)

	// listen and sign new certificates on demand
	ln, err := localca.Listen(":4443", ca, nil)
	if err != nil {
		log.Fatal(err)
	}

	// ready to serve
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello local http2 client")
	})
	srv := &http.Server{Addr: ":4443"}
	err = srv.Serve(ln)
	if err != nil {
		log.Fatal(err)
	}

Documentation at http://godoc.org/github.com/mb0/localca
