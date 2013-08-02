open Lwt

let no_q_pkt = Dns.Packet.({
  id = 0;
  detail = {
    qr = Query;
    opcode = Standard;
    aa = false; tc = false; rd = false; ra = false; rcode = NoError;
  };
  questions = []; answers = []; authorities = []; additionals = [];
})

let go () =
  Dns_resolver.create ~config:(`Static (["127.0.0.1",53],[])) ()
  >>= fun resolver ->
  Dns_resolver.send_pkt resolver no_q_pkt
  >|= Mldig_lib.print_answers

;;
Lwt_main.run (go ())
