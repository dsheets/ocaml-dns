(*
 * Copyright (c) 2005-2012 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2005 David Scott <djs@fraserresearch.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

open Printf
open Dns.Name
open Dns.Packet

let print_section s = printf ";; %s SECTION:\n" (String.uppercase s)

(* TODO: Should Name do this? *)
let string_of_name n = (domain_name_to_string n)^"."

let print_answers p =
    printf ";; global options: \n";
    let { detail; id; questions; answers; authorities; additionals } = p in
    let if_flag a b = if a then None else Some b in
    let flags = [
      (match detail.qr with |Query -> None |Response -> Some "qr");
      (if_flag detail.aa "aa");
      (if_flag detail.tc "tc");
      (if_flag detail.rd "rd");
      (if_flag detail.ra "ra");
    ] in
    let flags = String.concat " " (List.fold_left (fun a ->
      function |None -> a |Some x -> x :: a) [] flags) in
    printf ";; ->>HEADER<<- opcode: %s, status: %s, id: %u\n"
      (String.uppercase (opcode_to_string detail.opcode))
      (String.uppercase (rcode_to_string detail.rcode)) id;
    let al = List.length in
    printf ";; flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n\n"
      flags (al questions) (al answers) (al authorities) (al additionals);
    if al questions > 0 then begin
      print_section "question";
      List.iter (fun q -> printf ";%-23s %-8s %-8s %s\n"
        (string_of_name q.q_name) ""
        (q_class_to_string q.q_class)
        (q_type_to_string q.q_type)
      ) questions;
      print_newline ();
    end;
    let print_rr rr = printf "%-24s %-8lu %-8s %-8s %s\n"
        (string_of_name rr.name) rr.ttl (rr_class_to_string rr.cls) in
    List.iter (fun (nm,ob) ->
      if al ob > 0 then print_section nm;
      List.iter (fun rr ->
        match rr.rdata with
        |A ip-> print_rr rr "A" (Ipaddr.V4.to_string ip);
        |SOA (n1,n2,a1,a2,a3,a4,a5) ->
          print_rr rr "SOA"
            (sprintf "%s %s %lu %lu %lu %lu %lu" (string_of_name n1)
              (string_of_name n2) a1 a2 a3 a4 a5);
        |MX (pref,host) ->
          print_rr rr "MX" (sprintf "%d %s" pref (string_of_name host));
        |CNAME a -> print_rr rr "CNAME" (string_of_name a)
        |NS a -> print_rr rr "NS" (string_of_name a)
        |_ -> printf "unknown\n"
      ) ob;
      if al ob > 0 then print_newline ()
    ) ["answer",answers; "authority",authorities; "additional",additionals]
