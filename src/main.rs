use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::CString;
use std::rc::{Rc, Weak};

use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Write;

use anyhow::{bail, Error};
use flate2::read;
use libc::time_t;

mod time;
use time::{Tm, CAL_MTOD};

fn print_usage() {
    let pkg_version = env!("CARGO_PKG_VERSION");
    println!(
        "\
pmg-log-tracker {pkg_version}
Proxmox Mailgateway Log Tracker. Tool to scan mail logs.

USAGE:
    pmg-log-tracker [OPTIONS]

OPTIONS:
    -e, --endtime <TIME>            End time (YYYY-MM-DD HH:MM:SS) or seconds since epoch
    -f, --from <SENDER>             Mails from SENDER
    -g, --exclude-greylist          Exclude greylist entries
    -h, --host <HOST>               Hostname or Server IP
        --help                      Print help information
    -i, --inputfile <INPUTFILE>     Input file to use instead of /var/log/syslog, or '-' for stdin
    -l, --limit <MAX>               Print MAX entries [default: 0]
    -m, --message-id <MSGID>        Message ID (exact match)
    -n, --exclude-ndr               Exclude NDR entries
    -q, --queue-id <QID>            Queue ID (exact match), can be specified multiple times
    -s, --starttime <TIME>          Start time (YYYY-MM-DD HH:MM:SS) or seconds since epoch
    -t, --to <RECIPIENT>            Mails to RECIPIENT
    -v, --verbose                   Verbose output, can be specified multiple times
    -V, --version                   Print version information
    -x, --search-string <STRING>    Search for string",
    );
}

fn main() -> Result<(), Error> {
    let mut args = pico_args::Arguments::from_env();
    if args.contains("--help") {
        print_usage();
        return Ok(());
    }

    let mut parser = Parser::new()?;
    parser.handle_args(&mut args)?;

    let remaining_options = args.finish();
    if !remaining_options.is_empty() {
        bail!(
            "Found invalid arguments: {:?}",
            remaining_options.join(", ".as_ref())
        )
    }

    println!("# LogReader: {}", std::process::id());
    println!("# Query options");
    if !parser.options.from.is_empty() {
        println!("# Sender: {}", parser.options.from);
    }
    if !parser.options.to.is_empty() {
        println!("# Recipient: {}", parser.options.to);
    }
    if !parser.options.host.is_empty() {
        println!("# Server: {}", parser.options.host);
    }
    if !parser.options.msgid.is_empty() {
        println!("# MsgID: {}", parser.options.msgid);
    }
    for m in parser.options.match_list.iter() {
        match m {
            Match::Qid(b) => println!("# QID: {}", std::str::from_utf8(b)?),
            Match::RelLineNr(t, l) => println!("# QID: T{:8X}L{:08X}", *t, *l as u32),
        }
    }

    if !parser.options.string_match.is_empty() {
        println!("# Match: {}", parser.options.string_match);
    }

    println!(
        "# Start: {} ({})",
        time::strftime(c_str!("%F %T"), &parser.start_tm)?,
        parser.options.start
    );
    println!(
        "# End: {} ({})",
        time::strftime(c_str!("%F %T"), &parser.end_tm)?,
        parser.options.end
    );

    println!("# End Query Options\n");
    parser.parse_files()?;

    Ok(())
}

// handle log entries for service 'pmg-smtp-filter'
// we match 4 entries, all beginning with a QID
// accept mail, move mail, block mail and the processing time
fn handle_pmg_smtp_filter_message(msg: &[u8], parser: &mut Parser, complete_line: &[u8]) {
    let (qid, data) = match parse_qid(msg, 25) {
        Some((q, m)) => (q, m),
        None => return,
    };
    // skip ': ' following the QID
    let data = &data[2..];

    let fe = get_or_create_fentry(&mut parser.fentries, qid);

    if parser.string_match {
        fe.borrow_mut().string_match = parser.string_match;
    }

    fe.borrow_mut()
        .log
        .push((complete_line.into(), parser.lines));

    // we're interested in the 'to' address and the QID when we accept the mail
    if data.starts_with(b"accept mail to <") {
        let data = &data[16..];
        let to_count = data.iter().take_while(|b| (**b as char) != '>').count();
        let (to, data) = data.split_at(to_count);
        if !data.starts_with(b"> (") {
            return;
        }
        let data = &data[3..];
        let qid_count = data.iter().take_while(|b| (**b as char) != ')').count();
        let qid = &data[..qid_count];

        // add a ToEntry with the DStatus 'Accept' to the FEntry
        fe.borrow_mut()
            .add_accept(to, qid, parser.current_record_state.timestamp);

        // if there's a QEntry with the qid and it's not yet filtered
        // set it to before-queue filtered
        if let Some(qe) = parser.qentries.get(qid) {
            if !qe.borrow().filtered {
                qe.borrow_mut().bq_filtered = true;
                qe.borrow_mut().filter = Some(Rc::clone(&fe));
                fe.borrow_mut().qentry = Some(Rc::downgrade(qe));
            }
        }

        return;
    }

    // same as for the 'accept' case, we're interested in both the 'to'
    // address as well as the QID
    if data.starts_with(b"moved mail for <") {
        let data = &data[16..];
        let to_count = data.iter().take_while(|b| (**b as char) != '>').count();
        let (to, data) = data.split_at(to_count);

        let qid_index = match find(data, b"quarantine - ") {
            Some(i) => i,
            None => return,
        };
        let data = &data[qid_index + 13..];
        let (qid, _) = match parse_qid(data, 25) {
            Some(t) => t,
            None => return,
        };

        // add a ToEntry with the DStatus 'Quarantine' to the FEntry
        fe.borrow_mut()
            .add_quarantine(to, qid, parser.current_record_state.timestamp);
        return;
    }

    // in the 'block' case we're only interested in the 'to' address, there's
    // no queue for these mails
    if data.starts_with(b"block mail to <") {
        let data = &data[15..];
        let to_count = data.iter().take_while(|b| (**b as char) != '>').count();
        let to = &data[..to_count];

        fe.borrow_mut()
            .add_block(to, parser.current_record_state.timestamp);
        return;
    }

    // here the pmg-smtp-filter is finished and we get the processing time
    if data.starts_with(b"processing time: ") {
        let data = &data[17..];
        let time_count = data.iter().take_while(|b| !b.is_ascii_whitespace()).count();
        let time = &data[..time_count];

        fe.borrow_mut().set_processing_time(time);
    }
}

// handle log entries for postscreen
// here only the NOQUEUE: reject is of interest
// these are the mails that were rejected before even entering the smtpd by
// e.g. checking DNSBL sites
fn handle_postscreen_message(msg: &[u8], parser: &mut Parser, complete_line: &[u8]) {
    if !msg.starts_with(b"NOQUEUE: reject: RCPT from ") {
        return;
    }
    // skip the string from above
    let data = &msg[27..];
    let client_index = match find(data, b"; client [") {
        Some(i) => i,
        None => return,
    };
    let data = &data[client_index + 10..];

    let client_count = data.iter().take_while(|b| (**b as char) != ']').count();
    let (client, data) = data.split_at(client_count);

    let from_index = match find(data, b"; from=<") {
        Some(i) => i,
        None => return,
    };
    let data = &data[from_index + 8..];

    let from_count = data.iter().take_while(|b| (**b as char) != '>').count();
    let (from, data) = data.split_at(from_count);

    if !data.starts_with(b">, to=<") {
        return;
    }
    let data = &data[7..];
    let to_count = data.iter().take_while(|b| (**b as char) != '>').count();
    let to = &data[..to_count];

    let se = get_or_create_sentry(
        &mut parser.sentries,
        parser.current_record_state.pid,
        parser.rel_line_nr,
        parser.current_record_state.timestamp,
    );

    if parser.string_match {
        se.borrow_mut().string_match = parser.string_match;
    }

    se.borrow_mut()
        .log
        .push((complete_line.into(), parser.lines));
    // for postscreeen noqueue log entries we add a NoqueueEntry to the SEntry
    se.borrow_mut().add_noqueue_entry(
        from,
        to,
        DStatus::Noqueue,
        parser.current_record_state.timestamp,
    );
    // set the connecting client
    se.borrow_mut().set_connect(client);
    // as there's no more service involved after the postscreen noqueue entry,
    // we set it to disconnected and print it
    se.borrow_mut().disconnected = true;
    se.borrow_mut().print(parser);
    parser.free_sentry(parser.current_record_state.pid);
}

// handle log entries for 'qmgr'
// these only appear in the 'after-queue filter' case or when the mail is
// 'accepted' in the 'before-queue filter' case
fn handle_qmgr_message(msg: &[u8], parser: &mut Parser, complete_line: &[u8]) {
    let (qid, data) = match parse_qid(msg, 15) {
        Some(t) => t,
        None => return,
    };
    let data = &data[2..];

    let qe = get_or_create_qentry(&mut parser.qentries, qid);

    if parser.string_match {
        qe.borrow_mut().string_match = parser.string_match;
    }
    qe.borrow_mut().cleanup = true;
    qe.borrow_mut()
        .log
        .push((complete_line.into(), parser.lines));

    // we parse 2 log entries, either one with a 'from' and a 'size' or one
    // that signals that the mail has been removed from the queue (after an
    // action was taken, e.g. accept, by the filter)
    if data.starts_with(b"from=<") {
        let data = &data[6..];

        let from_count = data.iter().take_while(|b| (**b as char) != '>').count();
        let (from, data) = data.split_at(from_count);

        if !data.starts_with(b">, size=") {
            return;
        }
        let data = &data[8..];

        let size_count = data
            .iter()
            .take_while(|b| (**b as char).is_ascii_digit())
            .count();
        let (size, _) = data.split_at(size_count);
        qe.borrow_mut().from = from.into();
        // it is safe here because we had a check before that limits it to just
        // ascii digits which is valid utf8
        qe.borrow_mut().size = unsafe { std::str::from_utf8_unchecked(size) }
            .parse()
            .unwrap();
    } else if data == b"removed" {
        qe.borrow_mut().removed = true;
        qe.borrow_mut().finalize(parser);
    }
}

// handle log entries for 'lmtp', 'smtp', 'error' and 'local'
fn handle_lmtp_message(msg: &[u8], parser: &mut Parser, complete_line: &[u8]) {
    if msg.starts_with(b"Trusted TLS connection established to")
        || msg.starts_with(b"Untrusted TLS connection established to")
    {
        // the only way to match outgoing TLS connections is by smtp pid
        // this message has to appear before the 'qmgr: <QID>: removed' entry in the log
        parser.smtp_tls_log_by_pid.insert(
            parser.current_record_state.pid,
            (complete_line.into(), parser.lines),
        );
        return;
    }

    let (qid, data) = match parse_qid(msg, 15) {
        Some((q, t)) => (q, t),
        None => return,
    };

    let qe = get_or_create_qentry(&mut parser.qentries, qid);

    if parser.string_match {
        qe.borrow_mut().string_match = parser.string_match;
    }
    qe.borrow_mut().cleanup = true;
    qe.borrow_mut()
        .log
        .push((complete_line.into(), parser.lines));

    // assume the TLS log entry always appears before as it is the same process
    if let Some(log_line) = parser
        .smtp_tls_log_by_pid
        .remove(&parser.current_record_state.pid)
    {
        qe.borrow_mut().log.push(log_line);
    }

    let data = &data[2..];
    if !data.starts_with(b"to=<") {
        return;
    }
    let data = &data[4..];
    let to_count = data.iter().take_while(|b| (**b as char) != '>').count();
    let (to, data) = data.split_at(to_count);

    let relay_index = match find(data, b"relay=") {
        Some(i) => i,
        None => return,
    };
    let data = &data[relay_index + 6..];
    let relay_count = data.iter().take_while(|b| (**b as char) != ',').count();
    let (relay, data) = data.split_at(relay_count);

    // parse the DSN (indicates the delivery status, e.g. 2 == success)
    // ignore everything after the first digit
    let dsn_index = match find(data, b"dsn=") {
        Some(i) => i,
        None => return,
    };
    let data = &data[dsn_index + 4..];
    let dsn = match data.iter().next() {
        Some(b) => {
            if b.is_ascii_digit() {
                (*b as char).to_digit(10).unwrap()
            } else {
                return;
            }
        }
        None => return,
    };

    let dstatus = DStatus::Dsn(dsn);

    qe.borrow_mut()
        .add_to_entry(to, relay, dstatus, parser.current_record_state.timestamp);

    // here the match happens between a QEntry and the corresponding FEntry
    // (only after-queue)
    if &*parser.current_record_state.service == b"postfix/lmtp" {
        let sent_index = match find(data, b"status=sent (250 2.") {
            Some(i) => i,
            None => return,
        };
        let mut data = &data[sent_index + 19..];
        if data.starts_with(b"5.0 OK") {
            data = &data[8..];
        } else if data.starts_with(b"7.0 BLOCKED") {
            data = &data[13..];
        } else {
            return;
        }

        // this is the QID of the associated pmg-smtp-filter
        let (qid, _) = match parse_qid(data, 25) {
            Some(t) => t,
            None => return,
        };

        // add a reference to the filter
        qe.borrow_mut().filtered = true;

        // if there's a FEntry with the filter QID, check to see if its
        // qentry matches this one
        if let Some(fe) = parser.fentries.get(qid) {
            qe.borrow_mut().filter = Some(Rc::clone(fe));
            // if we use fe.borrow().qentry() directly we run into a borrow
            // issue at runtime
            let q = fe.borrow().qentry();
            if let Some(q) = q {
                if !Rc::ptr_eq(&q, &qe) {
                    // QEntries don't match, set all flags to false and
                    // remove the referenced FEntry
                    q.borrow_mut().filtered = false;
                    q.borrow_mut().bq_filtered = false;
                    q.borrow_mut().filter = None;
                    // update FEntry's QEntry reference to the new one
                    fe.borrow_mut().qentry = Some(Rc::downgrade(&qe));
                }
            }
        }
    }
}

// handle log entries for 'smtpd'
fn handle_smtpd_message(msg: &[u8], parser: &mut Parser, complete_line: &[u8]) {
    let se = get_or_create_sentry(
        &mut parser.sentries,
        parser.current_record_state.pid,
        parser.rel_line_nr,
        parser.current_record_state.timestamp,
    );

    if parser.string_match {
        se.borrow_mut().string_match = parser.string_match;
    }
    se.borrow_mut()
        .log
        .push((complete_line.into(), parser.lines));

    if msg.starts_with(b"connect from ") {
        let addr = &msg[13..];
        // set the client address
        se.borrow_mut().set_connect(addr);
        return;
    }

    // on disconnect we can finalize and print the SEntry
    if msg.starts_with(b"disconnect from") {
        parser.sentries.remove(&parser.current_record_state.pid);
        se.borrow_mut().disconnected = true;

        if se.borrow_mut().remove_unneeded_refs(parser) == 0 {
            // no QEntries referenced in SEntry so just print the SEntry
            se.borrow_mut().print(parser);
            // free the referenced FEntry (only happens with before-queue)
            if let Some(f) = &se.borrow().filter() {
                parser.free_fentry(&f.borrow().logid);
            }
            parser.free_sentry(se.borrow().pid);
        } else {
            se.borrow_mut().finalize_refs(parser);
        }
        return;
    }

    // NOQUEUE in smtpd, happens after postscreen
    if msg.starts_with(b"NOQUEUE:") {
        let data = &msg[8..];
        let colon_index = match find(data, b":") {
            Some(i) => i,
            None => return,
        };
        let data = &data[colon_index + 1..];
        let colon_index = match find(data, b":") {
            Some(i) => i,
            None => return,
        };
        let data = &data[colon_index + 1..];
        let semicolon_index = match find(data, b";") {
            Some(i) => i,
            None => return,
        };

        // check for the string, if it matches then greylisting is the reason
        // for the NOQUEUE entry
        let (grey, data) = data.split_at(semicolon_index);
        let dstatus = if find(
            grey,
            b"Recipient address rejected: Service is unavailable (try later)",
        )
        .is_some()
        {
            DStatus::Greylist
        } else {
            DStatus::Noqueue
        };

        if !data.starts_with(b"; from=<") {
            return;
        }
        let data = &data[8..];
        let from_count = data.iter().take_while(|b| (**b as char) != '>').count();
        let (from, data) = data.split_at(from_count);

        if !data.starts_with(b"> to=<") {
            return;
        }
        let data = &data[6..];
        let to_count = data.iter().take_while(|b| (**b as char) != '>').count();
        let to = &data[..to_count];

        se.borrow_mut()
            .add_noqueue_entry(from, to, dstatus, parser.current_record_state.timestamp);
        return;
    }

    // only happens with before-queue
    // here we can match the pmg-smtp-filter
    // 'proxy-accept' happens if it is accepted for AT LEAST ONE receiver
    if msg.starts_with(b"proxy-accept: ") {
        let data = &msg[14..];
        if !data.starts_with(b"END-OF-MESSAGE: ") {
            return;
        }
        let data = &data[16..];
        if !data.starts_with(b"250 2.5.0 OK (") {
            return;
        }
        let data = &data[14..];
        if let Some((qid, data)) = parse_qid(data, 25) {
            let fe = get_or_create_fentry(&mut parser.fentries, qid);
            // set the FEntry to before-queue filtered
            fe.borrow_mut().is_bq = true;
            // if there's no 'accept mail to' entry because of quarantine
            // we have to match the pmg-smtp-filter here
            // for 'accepted' mails it is matched in the 'accept mail to'
            // log entry
            if !fe.borrow().is_accepted {
                // set the SEntry filter reference as we don't have a QEntry
                // in this case
                se.borrow_mut().filter = Some(Rc::downgrade(&fe));

                if let Some(from_index) = find(data, b"from=<") {
                    let data = &data[from_index + 6..];
                    let from_count = data.iter().take_while(|b| (**b as char) != '>').count();
                    let from = &data[..from_count];
                    // keep the from for later printing
                    // required for the correct 'TO:{}:{}...' syntax required
                    // by PMG/API2/MailTracker.pm
                    se.borrow_mut().bq_from = from.into();
                }
            } else if let Some(qe) = &fe.borrow().qentry() {
                // mail is 'accepted', add a reference to the QEntry to the
                // SEntry so we can wait for all to be finished before printing
                qe.borrow_mut().bq_sentry = Some(Rc::clone(&se));
                SEntry::add_ref(&se, qe, true);
            }
            // specify that before queue filtering is used and the mail was
            // accepted, but not necessarily by an 'accept' rule
            // (e.g. quarantine)
            se.borrow_mut().is_bq_accepted = true;
        }

        return;
    }

    // before queue filtering and rejected, here we can match the
    // pmg-smtp-filter same as in the 'proxy-accept' case
    // only happens if the mail was rejected for ALL receivers, otherwise
    // a 'proxy-accept' happens
    if msg.starts_with(b"proxy-reject: ") {
        let data = &msg[14..];
        if !data.starts_with(b"END-OF-MESSAGE: ") {
            return;
        }
        let data = &data[16..];

        // specify that before queue filtering is used and the mail
        // was rejected for all receivers
        se.borrow_mut().is_bq_rejected = true;

        if let Some(qid_index) = find(data, b"(") {
            let data = &data[qid_index + 1..];
            if let Some((qid, _)) = parse_qid(data, 25) {
                let fe = get_or_create_fentry(&mut parser.fentries, qid);
                // set the FEntry to before-queue filtered
                fe.borrow_mut().is_bq = true;
                // we never have a QEntry in this case, so just set the SEntry
                // filter reference
                se.borrow_mut().filter = Some(Rc::downgrade(&fe));
                if let Some(from_index) = find(data, b"from=<") {
                    let data = &data[from_index + 6..];
                    let from_count = data.iter().take_while(|b| (**b as char) != '>').count();
                    let from = &data[..from_count];
                    // same as for 'proxy-accept' above
                    se.borrow_mut().bq_from = from.into();
                }
            }
        } else if let Some(from_index) = find(data, b"from=<") {
            let data = &data[from_index + 6..];
            let from_count = data.iter().take_while(|b| (**b as char) != '>').count();
            let from = &data[..from_count];
            // same as for 'proxy-accept' above
            se.borrow_mut().bq_from = from.into();

            if let Some(to_index) = find(data, b"to=<") {
                let data = &data[to_index + 4..];
                let to_count = data.iter().take_while(|b| (**b as char) != '>').count();
                let to = &data[..to_count];

                se.borrow_mut().add_noqueue_entry(
                    from,
                    to,
                    DStatus::Noqueue,
                    parser.current_record_state.timestamp,
                );
            };
        }

        return;
    }

    // with none of the other messages matching, we try for a QID to match the
    // corresponding QEntry to the SEntry
    let (qid, data) = match parse_qid(msg, 15) {
        Some(t) => t,
        None => return,
    };
    let data = &data[2..];

    let qe = get_or_create_qentry(&mut parser.qentries, qid);

    if parser.string_match {
        qe.borrow_mut().string_match = parser.string_match;
    }

    SEntry::add_ref(&se, &qe, false);

    if !data.starts_with(b"client=") {
        return;
    }
    let data = &data[7..];
    let client_count = data
        .iter()
        .take_while(|b| !(**b as char).is_ascii_whitespace())
        .count();
    let client = &data[..client_count];

    qe.borrow_mut().set_client(client);
}

// handle log entries for 'cleanup'
// happens before the mail is passed to qmgr (after-queue or before-queue
// accepted only)
fn handle_cleanup_message(msg: &[u8], parser: &mut Parser, complete_line: &[u8]) {
    let (qid, data) = match parse_qid(msg, 15) {
        Some(t) => t,
        None => return,
    };
    let data = &data[2..];

    let qe = get_or_create_qentry(&mut parser.qentries, qid);

    if parser.string_match {
        qe.borrow_mut().string_match = parser.string_match;
    }
    qe.borrow_mut()
        .log
        .push((complete_line.into(), parser.lines));

    if !data.starts_with(b"message-id=") {
        return;
    }
    let data = &data[11..];
    let msgid_count = data
        .iter()
        .take_while(|b| !(**b as char).is_ascii_whitespace())
        .count();
    let msgid = &data[..msgid_count];

    if !msgid.is_empty() {
        if qe.borrow().msgid.is_empty() {
            qe.borrow_mut().msgid = msgid.into();
        }
        qe.borrow_mut().cleanup = true;

        // does not work correctly if there's a duplicate message id in the logfiles
        if let Some(q) = parser.msgid_lookup.remove(msgid) {
            let q_clone = Weak::clone(&q);
            if let Some(q) = q.upgrade() {
                // check to make sure it's not the same QEntry
                // this can happen if the cleanup line is duplicated in the log
                if Rc::ptr_eq(&q, &qe) {
                    parser.msgid_lookup.insert(msgid.into(), q_clone);
                } else {
                    qe.borrow_mut().aq_qentry = Some(q_clone);
                    q.borrow_mut().aq_qentry = Some(Rc::downgrade(&qe));
                }
            }
        } else {
            parser.msgid_lookup.insert(msgid.into(), Rc::downgrade(&qe));
        }
    }
}

#[derive(Default, Debug)]
struct NoqueueEntry {
    from: Box<[u8]>,
    to: Box<[u8]>,
    dstatus: DStatus,
    timestamp: time_t,
}

#[derive(Debug)]
struct ToEntry {
    to: Box<[u8]>,
    relay: Box<[u8]>,
    dstatus: DStatus,
    timestamp: time_t,
}

impl Default for ToEntry {
    fn default() -> Self {
        ToEntry {
            to: Default::default(),
            relay: (&b"none"[..]).into(),
            dstatus: Default::default(),
            timestamp: Default::default(),
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
enum DStatus {
    Invalid,
    Accept,
    Quarantine,
    Block,
    Greylist,
    Noqueue,
    BqPass,
    BqDefer,
    BqReject,
    Dsn(u32),
}

impl Default for DStatus {
    fn default() -> Self {
        DStatus::Invalid
    }
}

impl std::fmt::Display for DStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let c = match self {
            DStatus::Invalid => '\0', // other default
            DStatus::Accept => 'A',
            DStatus::Quarantine => 'Q',
            DStatus::Block => 'B',
            DStatus::Greylist => 'G',
            DStatus::Noqueue => 'N',
            DStatus::BqPass => 'P',
            DStatus::BqDefer => 'D',
            DStatus::BqReject => 'R',
            DStatus::Dsn(v) => std::char::from_digit(*v, 10).unwrap(),
        };
        write!(f, "{}", c)
    }
}

#[derive(Debug, Default)]
struct SEntry {
    log: Vec<(Box<[u8]>, u64)>,
    connect: Box<[u8]>,
    pid: u64,
    // references to QEntries, Weak so they are not kept alive longer than
    // necessary, RefCell for mutability (Rc<> is immutable)
    refs: Vec<Weak<RefCell<QEntry>>>,
    nq_entries: Vec<NoqueueEntry>,
    disconnected: bool,
    // only set in case of before queue filtering
    // used as a fallback in case no QEntry is referenced
    filter: Option<Weak<RefCell<FEntry>>>,
    string_match: bool,
    timestamp: time_t,
    rel_line_nr: u64,
    // before queue filtering with the mail accepted for at least one receiver
    is_bq_accepted: bool,
    // before queue filtering with the mail rejected for all receivers
    is_bq_rejected: bool,
    // from address saved for compatibility with after queue filtering
    bq_from: Box<[u8]>,
}

impl SEntry {
    fn add_noqueue_entry(&mut self, from: &[u8], to: &[u8], dstatus: DStatus, timestamp: time_t) {
        let ne = NoqueueEntry {
            to: to.into(),
            from: from.into(),
            dstatus,
            timestamp,
        };
        self.nq_entries.push(ne);
    }

    fn set_connect(&mut self, client: &[u8]) {
        if self.connect.is_empty() {
            self.connect = client.into();
        }
    }

    // if either 'from' or 'to' are set, check if it matches, if not, set
    // the status of the noqueue entry to Invalid
    // if exclude_greylist or exclude_ndr are set, check if it matches
    // and if so, set the status to Invalid so they are no longer included
    // don't print if any Invalid entry is found
    fn filter_matches(&mut self, parser: &Parser) -> bool {
        if !parser.options.from.is_empty()
            || !parser.options.to.is_empty()
            || parser.options.exclude_greylist
            || parser.options.exclude_ndr
        {
            let mut found = false;
            for nq in self.nq_entries.iter_mut().rev() {
                if (!parser.options.from.is_empty()
                    && find_lowercase(&nq.from, parser.options.from.as_bytes()).is_none())
                    || (parser.options.exclude_greylist && nq.dstatus == DStatus::Greylist)
                    || (parser.options.exclude_ndr && nq.from.is_empty())
                    || (!parser.options.to.is_empty()
                        && ((!nq.to.is_empty()
                            && find_lowercase(&nq.to, parser.options.to.as_bytes()).is_none())
                            || nq.to.is_empty()))
                {
                    nq.dstatus = DStatus::Invalid;
                }

                if nq.dstatus != DStatus::Invalid {
                    found = true;
                }
            }

            // we can early exit the printing if there's no valid Noqueue entry
            // and we're in the after-queue case
            if !found && self.filter.is_none() {
                return false;
            }

            // self.filter only contains an object in the before-queue case
            // as we have the FEntry referenced in the SEntry when there's no
            // queue involved, we can't just check the Noqueue entries, but
            // have to check for a filter and if it exists, we have to check
            // them for matching 'from' and 'to' if either of those options
            // are set.
            // if neither of them is filtered, we can skip this check
            if let Some(fe) = &self.filter() {
                if !parser.options.from.is_empty()
                    && find_lowercase(&self.bq_from, parser.options.from.as_bytes()).is_none()
                {
                    return false;
                }
                let to_option_set = !parser.options.to.is_empty();
                if to_option_set && fe.borrow().is_bq && !fe.borrow().is_accepted {
                    fe.borrow_mut().to_entries.retain(|to| {
                        if find_lowercase(&to.to, parser.options.to.as_bytes()).is_some() {
                            found = true;
                            return true;
                        }
                        false
                    });
                    if !found {
                        return false;
                    }
                }
            }
        }
        true
    }

    fn print(&mut self, parser: &mut Parser) {
        // don't print if the output is filtered by the message-id
        // the message-id is only available in a QEntry
        if !parser.options.msgid.is_empty() {
            return;
        }

        // don't print if the output is filtered by a host but the connect
        // field is empty or does not match
        if !parser.options.host.is_empty() {
            if self.connect.is_empty() {
                return;
            }
            if find_lowercase(&self.connect, parser.options.host.as_bytes()).is_none() {
                return;
            }
        }

        // don't print if the output is filtered by time and line number
        // and none match
        if !parser.options.match_list.is_empty() {
            let mut found = false;
            for m in parser.options.match_list.iter() {
                match m {
                    Match::Qid(_) => return,
                    Match::RelLineNr(t, l) => {
                        if *t == self.timestamp && *l == self.rel_line_nr {
                            found = true;
                            break;
                        }
                    }
                }
            }
            if !found {
                return;
            }
        }

        if !self.filter_matches(parser) {
            return;
        }

        // don't print if there's a string match specified, but none of the log entries matches.
        // in the before-queue case we also have to check the attached filter for a match
        if !parser.options.string_match.is_empty() {
            if let Some(fe) = &self.filter() {
                if !self.string_match && !fe.borrow().string_match {
                    return;
                }
            } else if !self.string_match {
                return;
            }
        }

        if parser.options.verbose > 0 {
            parser.write_all_ok(format!(
                "SMTPD: T{:8X}L{:08X}\n",
                self.timestamp, self.rel_line_nr as u32
            ));
            parser.write_all_ok(format!("CTIME: {:8X}\n", parser.ctime).as_bytes());

            if !self.connect.is_empty() {
                parser.write_all_ok(b"CLIENT: ");
                parser.write_all_ok(&self.connect);
                parser.write_all_ok(b"\n");
            }
        }

        // only print the entry if the status is not invalid
        // rev() for compatibility with the C code which uses a linked list
        // that adds entries at the front, while a Vec in Rust adds it at the
        // back
        for nq in self.nq_entries.iter().rev() {
            if nq.dstatus != DStatus::Invalid {
                parser.write_all_ok(format!(
                    "TO:{:X}:T{:08X}L{:08X}:{}: from <",
                    nq.timestamp, self.timestamp, self.rel_line_nr, nq.dstatus,
                ));
                parser.write_all_ok(&nq.from);
                parser.write_all_ok(b"> to <");
                parser.write_all_ok(&nq.to);
                parser.write_all_ok(b">\n");
                parser.count += 1;
            }
        }

        let print_filter_to_entries_fn =
            |fe: &Rc<RefCell<FEntry>>, parser: &mut Parser, se: &SEntry| {
                for to in fe.borrow().to_entries.iter().rev() {
                    parser.write_all_ok(format!(
                        "TO:{:X}:T{:08X}L{:08X}:{}: from <",
                        to.timestamp, se.timestamp, se.rel_line_nr, to.dstatus,
                    ));
                    parser.write_all_ok(&se.bq_from);
                    parser.write_all_ok(b"> to <");
                    parser.write_all_ok(&to.to);
                    parser.write_all_ok(b">\n");
                    parser.count += 1;
                }
            };

        // only true in before queue filtering case
        if let Some(fe) = &self.filter() {
            // limited to !fe.is_accepted because otherwise we would have
            // a QEntry with all required information instead
            if fe.borrow().is_bq
                && !fe.borrow().is_accepted
                && (self.is_bq_accepted || self.is_bq_rejected)
            {
                print_filter_to_entries_fn(fe, parser, self);
            }
        }

        let print_log = |parser: &mut Parser, logs: &Vec<(Box<[u8]>, u64)>| {
            for (log, line) in logs.iter() {
                parser.write_all_ok(format!("L{:08X} ", *line as u32));
                parser.write_all_ok(log);
                parser.write_all_ok(b"\n");
            }
        };

        // if '-vv' is passed to the log tracker, print all the logs
        if parser.options.verbose > 1 {
            parser.write_all_ok(b"LOGS:\n");
            let mut logs = self.log.clone();
            if let Some(f) = &self.filter() {
                logs.append(&mut f.borrow().log.clone());
                // as the logs come from 1 SEntry and 1 FEntry,
                // interleave them via sort based on line number
                logs.sort_by(|a, b| a.1.cmp(&b.1));
            }

            print_log(parser, &logs);
        }
        parser.write_all_ok(b"\n");
    }

    fn delete_ref(&mut self, qentry: &Rc<RefCell<QEntry>>) {
        self.refs.retain(|q| {
            let q = match q.upgrade() {
                Some(q) => q,
                None => return false,
            };
            if Rc::ptr_eq(&q, qentry) {
                return false;
            }
            true
        });
    }

    fn remove_unneeded_refs(&mut self, parser: &mut Parser) -> u32 {
        let mut count: u32 = 0;
        let mut to_delete = Vec::new();
        self.refs.retain(|q| {
            let q = match q.upgrade() {
                Some(q) => q,
                None => return false,
            };
            let is_cleanup = q.borrow().cleanup;
            // add those that require freeing to a separate Vec as self is
            // borrowed mutable here and can't be borrowed again for the
            // parser.free_qentry() call
            if !is_cleanup {
                to_delete.push(q);
                false
            } else {
                count += 1;
                true
            }
        });

        for q in to_delete.iter().rev() {
            parser.free_qentry(&q.borrow().qid, Some(self));
        }
        count
    }

    // print and free all QEntries that are removed and if a filter is set,
    // if the filter is finished
    fn finalize_refs(&mut self, parser: &mut Parser) {
        let mut qentries = Vec::new();
        for q in self.refs.iter() {
            let q = match q.upgrade() {
                Some(q) => q,
                None => continue,
            };

            if !q.borrow().removed {
                continue;
            }

            let fe = &q.borrow().filter;
            if let Some(f) = fe {
                if !q.borrow().bq_filtered && !f.borrow().finished {
                    continue;
                }
            }

            if !self.is_bq_accepted && q.borrow().bq_sentry.is_some() {
                if let Some(se) = &q.borrow().bq_sentry {
                    // we're already disconnected, but the SEntry referenced
                    // by the QEntry might not yet be done
                    if !se.borrow().disconnected {
                        // add a reference to the SEntry referenced by the
                        // QEntry so it gets deleted when both the SEntry
                        // and the QEntry is done
                        Self::add_ref(se, &q, true);
                        continue;
                    }
                }
            }

            qentries.push(Rc::clone(&q));
        }

        for q in qentries.iter().rev() {
            q.borrow_mut().print(parser, Some(self));
            parser.free_qentry(&q.borrow().qid, Some(self));

            if let Some(f) = &q.borrow().filter {
                parser.free_fentry(&f.borrow().logid);
            }
        }
    }

    fn add_ref(sentry: &Rc<RefCell<SEntry>>, qentry: &Rc<RefCell<QEntry>>, bq: bool) {
        let smtpd = qentry.borrow().smtpd.clone();
        if !bq {
            if let Some(s) = smtpd {
                if !Rc::ptr_eq(sentry, &s) {
                    eprintln!("Error: qentry ref already set");
                }
                return;
            }
        }

        for q in sentry.borrow().refs.iter() {
            let q = match q.upgrade() {
                Some(q) => q,
                None => continue,
            };
            if Rc::ptr_eq(&q, qentry) {
                return;
            }
        }

        sentry.borrow_mut().refs.push(Rc::downgrade(qentry));
        if !bq {
            qentry.borrow_mut().smtpd = Some(Rc::clone(sentry));
        }
    }

    fn filter(&self) -> Option<Rc<RefCell<FEntry>>> {
        self.filter.clone().and_then(|f| f.upgrade())
    }
}

#[derive(Default, Debug)]
struct QEntry {
    log: Vec<(Box<[u8]>, u64)>,
    smtpd: Option<Rc<RefCell<SEntry>>>,
    filter: Option<Rc<RefCell<FEntry>>>,
    qid: Box<[u8]>,
    from: Box<[u8]>,
    client: Box<[u8]>,
    msgid: Box<[u8]>,
    size: u64,
    to_entries: Vec<ToEntry>,
    cleanup: bool,
    removed: bool,
    filtered: bool,
    string_match: bool,
    bq_filtered: bool,
    // will differ from smtpd
    bq_sentry: Option<Rc<RefCell<SEntry>>>,
    aq_qentry: Option<Weak<RefCell<QEntry>>>,
}

impl QEntry {
    fn add_to_entry(&mut self, to: &[u8], relay: &[u8], dstatus: DStatus, timestamp: time_t) {
        let te = ToEntry {
            to: to.into(),
            relay: relay.into(),
            dstatus,
            timestamp,
        };
        self.to_entries.push(te);
    }

    // finalize and print the QEntry
    fn finalize(&mut self, parser: &mut Parser) {
        // if it is not removed, skip
        if self.removed {
            if let Some(se) = &self.smtpd {
                // verify that the SEntry it is attached to is disconnected
                if !se.borrow().disconnected {
                    return;
                }
            }
            if let Some(s) = &self.bq_sentry {
                if self.bq_filtered && !s.borrow().disconnected {
                    return;
                }
            }

            if let Some(qe) = &self.aq_qentry {
                if let Some(qe) = qe.upgrade() {
                    if !qe.borrow().removed {
                        return;
                    }
                    qe.borrow_mut().aq_qentry = None;
                    qe.borrow_mut().finalize(parser);
                }
            }

            if let Some(fe) = self.filter.clone() {
                // verify that the attached FEntry is finished if it is not
                // before queue filtered
                if !self.bq_filtered && !fe.borrow().finished {
                    return;
                }

                // if there's an SEntry, print with the SEntry
                // otherwise just print the QEntry (this can happen in certain
                // situations)
                match self.smtpd.clone() {
                    Some(s) => self.print(parser, Some(&*s.borrow())),
                    None => self.print(parser, None),
                };
                if let Some(se) = &self.smtpd {
                    parser.free_qentry(&self.qid, Some(&mut *se.borrow_mut()));
                } else {
                    parser.free_qentry(&self.qid, None);
                }

                if !self.bq_filtered {
                    parser.free_fentry(&fe.borrow().logid);
                }
            } else if let Some(s) = self.smtpd.clone() {
                self.print(parser, Some(&*s.borrow()));
                parser.free_qentry(&self.qid, Some(&mut *s.borrow_mut()));
            } else {
                self.print(parser, None);
                parser.free_qentry(&self.qid, None);
            }
        }
    }

    fn msgid_matches(&self, parser: &Parser) -> bool {
        if !parser.options.msgid.is_empty() {
            if self.msgid.is_empty() {
                return false;
            }
            let qentry_msgid_lowercase = self.msgid.to_ascii_lowercase();
            let msgid_lowercase = parser.options.msgid.as_bytes().to_ascii_lowercase();
            if qentry_msgid_lowercase != msgid_lowercase {
                return false;
            }
        }
        true
    }

    fn match_list_matches(&self, parser: &Parser, se: Option<&SEntry>) -> bool {
        let fe = &self.filter;
        if !parser.options.match_list.is_empty() {
            let mut found = false;
            for m in parser.options.match_list.iter() {
                match m {
                    Match::Qid(q) => {
                        if let Some(f) = fe {
                            if &f.borrow().logid == q {
                                found = true;
                                break;
                            }
                        }
                        if &self.qid == q {
                            found = true;
                            break;
                        }
                    }
                    Match::RelLineNr(t, l) => {
                        if let Some(s) = se {
                            if s.timestamp == *t && s.rel_line_nr == *l {
                                found = true;
                                break;
                            }
                        }
                    }
                }
            }
            if !found {
                return false;
            }
        }
        true
    }

    fn host_matches(&self, parser: &Parser, se: Option<&SEntry>) -> bool {
        if !parser.options.host.is_empty() {
            let mut found = false;
            if let Some(s) = se {
                if !s.connect.is_empty()
                    && find_lowercase(&s.connect, parser.options.host.as_bytes()).is_some()
                {
                    found = true;
                }
            }
            if !self.client.is_empty()
                && find_lowercase(&self.client, parser.options.host.as_bytes()).is_some()
            {
                found = true;
            }

            if !found {
                return false;
            }
        }
        true
    }

    fn from_to_matches(&mut self, parser: &Parser) -> bool {
        if !parser.options.from.is_empty() {
            if self.from.is_empty() {
                return false;
            }
            if find_lowercase(&self.from, parser.options.from.as_bytes()).is_none() {
                return false;
            }
        } else if parser.options.exclude_ndr && self.from.is_empty() {
            return false;
        }

        if !parser.options.to.is_empty() {
            let mut found = false;
            self.to_entries.retain(|to| {
                if find_lowercase(&to.to, parser.options.to.as_bytes()).is_none() {
                    false
                } else {
                    found = true;
                    true
                }
            });
            if let Some(fe) = &self.filter {
                fe.borrow_mut().to_entries.retain(|to| {
                    if find_lowercase(&to.to, parser.options.to.as_bytes()).is_none() {
                        false
                    } else {
                        found = true;
                        true
                    }
                });
            }
            if !found {
                return false;
            }
        }
        true
    }

    fn string_matches(&self, parser: &Parser, se: Option<&SEntry>) -> bool {
        let fe = &self.filter;
        if !parser.options.string_match.is_empty() {
            let mut string_match = self.string_match;

            if let Some(s) = se {
                if s.string_match {
                    string_match = true;
                }
            }
            if let Some(f) = fe {
                if f.borrow().string_match {
                    string_match = true;
                }
            }
            if !string_match {
                return false;
            }
        }
        true
    }

    // is_se_bq_sentry is true if the QEntry::bq_sentry is the same as passed
    // into the print() function via reference
    fn print_qentry_boilerplate(
        &mut self,
        parser: &mut Parser,
        is_se_bq_sentry: bool,
        se: Option<&SEntry>,
    ) {
        parser.write_all_ok(b"QENTRY: ");
        parser.write_all_ok(&self.qid);
        parser.write_all_ok(b"\n");
        parser.write_all_ok(format!("CTIME: {:8X}\n", parser.ctime));
        parser.write_all_ok(format!("SIZE: {}\n", self.size));

        if !self.client.is_empty() {
            parser.write_all_ok(b"CLIENT: ");
            parser.write_all_ok(&self.client);
            parser.write_all_ok(b"\n");
        } else if !is_se_bq_sentry {
            if let Some(s) = se {
                if !s.connect.is_empty() {
                    parser.write_all_ok(b"CLIENT: ");
                    parser.write_all_ok(&s.connect);
                    parser.write_all_ok(b"\n");
                }
            }
        } else if let Some(s) = &self.smtpd {
            if !s.borrow().connect.is_empty() {
                parser.write_all_ok(b"CLIENT: ");
                parser.write_all_ok(&s.borrow().connect);
                parser.write_all_ok(b"\n");
            }
        }

        if !self.msgid.is_empty() {
            parser.write_all_ok(b"MSGID: ");
            parser.write_all_ok(&self.msgid);
            parser.write_all_ok(b"\n");
        }
    }

    fn print(&mut self, parser: &mut Parser, se: Option<&SEntry>) {
        let fe = self.filter.clone();

        if !self.msgid_matches(parser)
            || !self.match_list_matches(parser, se)
            || !self.host_matches(parser, se)
            || !self.from_to_matches(parser)
            || !self.string_matches(parser, se)
        {
            return;
        }

        // necessary so we do not attempt to mutable borrow it a second time
        // which will panic
        let is_se_bq_sentry = match (&self.bq_sentry, se) {
            (Some(s), Some(se)) => std::ptr::eq(s.as_ptr(), se),
            _ => false,
        };

        if is_se_bq_sentry {
            if let Some(s) = &se {
                if !s.disconnected {
                    return;
                }
            }
        }

        if parser.options.verbose > 0 {
            self.print_qentry_boilerplate(parser, is_se_bq_sentry, se);
        }

        if self.bq_filtered {
            for to in self.to_entries.iter_mut() {
                to.dstatus = match to.dstatus {
                    // the dsn (enhanced status code can only have a class of 2, 4 or 5
                    // see https://tools.ietf.org/html/rfc3463
                    DStatus::Dsn(2) => DStatus::BqPass,
                    DStatus::Dsn(4) => DStatus::BqDefer,
                    DStatus::Dsn(5) => DStatus::BqReject,
                    _ => to.dstatus,
                };
            }
        }

        // rev() to match the C code iteration direction (linked list vs Vec)
        for to in self.to_entries.iter().rev() {
            if !to.to.is_empty() {
                let final_rc;
                let final_borrow;
                let mut final_to: &ToEntry = to;

                // if status == success and there's a filter attached that has
                // a matching 'to' in one of the ToEntries, set the ToEntry to
                // the one in the filter
                if to.dstatus == DStatus::Dsn(2) {
                    if let Some(f) = &fe {
                        if !self.bq_filtered || (f.borrow().finished && f.borrow().is_bq) {
                            final_rc = f;
                            final_borrow = final_rc.borrow();
                            for to2 in final_borrow.to_entries.iter().rev() {
                                if to.to == to2.to {
                                    final_to = to2;
                                    break;
                                }
                            }
                        }
                    }
                }

                parser.write_all_ok(format!("TO:{:X}:", to.timestamp));
                parser.write_all_ok(&self.qid);
                parser.write_all_ok(format!(":{}: from <", final_to.dstatus));
                parser.write_all_ok(&self.from);
                parser.write_all_ok(b"> to <");
                parser.write_all_ok(&final_to.to);
                parser.write_all_ok(b"> (");
                // if we use the relay from the filter ToEntry, it will be
                // marked 'is_relay' in PMG/API2/MailTracker.pm and not shown
                // in the GUI in the case of before queue filtering
                if !self.bq_filtered {
                    parser.write_all_ok(&final_to.relay);
                } else {
                    parser.write_all_ok(&to.relay);
                }
                parser.write_all_ok(b")\n");
                parser.count += 1;
            }
        }

        if self.bq_filtered {
            if let Some(fe) = &fe {
                if fe.borrow().finished && fe.borrow().is_bq {
                    fe.borrow_mut().to_entries.retain(|to| {
                        for to2 in self.to_entries.iter().rev() {
                            if to.to == to2.to {
                                return false;
                            }
                        }
                        true
                    });

                    for to in fe.borrow().to_entries.iter().rev() {
                        parser.write_all_ok(format!("TO:{:X}:", to.timestamp));
                        parser.write_all_ok(&self.qid);
                        parser.write_all_ok(format!(":{}: from <", to.dstatus));
                        parser.write_all_ok(&self.from);
                        parser.write_all_ok(b"> to <");
                        parser.write_all_ok(&to.to);
                        parser.write_all_ok(b"> (");
                        parser.write_all_ok(&to.relay);
                        parser.write_all_ok(b")\n");
                        parser.count += 1;
                    }
                }
            }
        }

        // print logs if '-vv' is specified
        if parser.options.verbose > 1 {
            let print_log = |parser: &mut Parser, logs: &Vec<(Box<[u8]>, u64)>| {
                for (log, line) in logs.iter() {
                    parser.write_all_ok(format!("L{:08X} ", *line as u32));
                    parser.write_all_ok(log);
                    parser.write_all_ok(b"\n");
                }
            };
            if !is_se_bq_sentry {
                if let Some(s) = se {
                    let mut logs = s.log.clone();
                    if let Some(bq_se) = &self.bq_sentry {
                        logs.append(&mut bq_se.borrow().log.clone());
                        // as the logs come from 2 different SEntries,
                        // interleave them via sort based on line number
                        logs.sort_by(|a, b| a.1.cmp(&b.1));
                    }
                    if !logs.is_empty() {
                        parser.write_all_ok(b"SMTP:\n");
                        print_log(parser, &logs);
                    }
                }
            } else if let Some(s) = &self.smtpd {
                let mut logs = s.borrow().log.clone();
                if let Some(se) = se {
                    logs.append(&mut se.log.clone());
                    // as the logs come from 2 different SEntries,
                    // interleave them via sort based on line number
                    logs.sort_by(|a, b| a.1.cmp(&b.1));
                }
                if !logs.is_empty() {
                    parser.write_all_ok(b"SMTP:\n");
                    print_log(parser, &logs);
                }
            }

            if let Some(f) = fe {
                if (!self.bq_filtered || (f.borrow().finished && f.borrow().is_bq))
                    && !f.borrow().log.is_empty()
                {
                    parser.write_all_ok(format!("FILTER: {}\n", unsafe {
                        std::str::from_utf8_unchecked(&f.borrow().logid)
                    }));
                    print_log(parser, &f.borrow().log);
                }
            }

            if !self.log.is_empty() {
                parser.write_all_ok(b"QMGR:\n");
                self.log.sort_by(|a, b| a.1.cmp(&b.1));
                print_log(parser, &self.log);
            }
        }
        parser.write_all_ok(b"\n")
    }

    fn set_client(&mut self, client: &[u8]) {
        if self.client.is_empty() {
            self.client = client.into();
        }
    }
}

#[derive(Default, Debug)]
struct FEntry {
    log: Vec<(Box<[u8]>, u64)>,
    logid: Box<[u8]>,
    to_entries: Vec<ToEntry>,
    processing_time: Box<[u8]>,
    string_match: bool,
    finished: bool,
    is_accepted: bool,
    qentry: Option<Weak<RefCell<QEntry>>>,
    is_bq: bool,
}

impl FEntry {
    fn add_accept(&mut self, to: &[u8], qid: &[u8], timestamp: time_t) {
        let te = ToEntry {
            to: to.into(),
            relay: qid.into(),
            dstatus: DStatus::Accept,
            timestamp,
        };
        self.to_entries.push(te);
        self.is_accepted = true;
    }

    fn add_quarantine(&mut self, to: &[u8], qid: &[u8], timestamp: time_t) {
        let te = ToEntry {
            to: to.into(),
            relay: qid.into(),
            dstatus: DStatus::Quarantine,
            timestamp,
        };
        self.to_entries.push(te);
    }

    fn add_block(&mut self, to: &[u8], timestamp: time_t) {
        let te = ToEntry {
            to: to.into(),
            relay: (&b"none"[..]).into(),
            dstatus: DStatus::Block,
            timestamp,
        };
        self.to_entries.push(te);
    }

    fn set_processing_time(&mut self, time: &[u8]) {
        self.processing_time = time.into();
        self.finished = true;
    }

    fn qentry(&self) -> Option<Rc<RefCell<QEntry>>> {
        self.qentry.clone().and_then(|q| q.upgrade())
    }
}

#[derive(Debug)]
struct Parser {
    sentries: HashMap<u64, Rc<RefCell<SEntry>>>,
    fentries: HashMap<Box<[u8]>, Rc<RefCell<FEntry>>>,
    qentries: HashMap<Box<[u8]>, Rc<RefCell<QEntry>>>,
    msgid_lookup: HashMap<Box<[u8]>, Weak<RefCell<QEntry>>>,

    smtp_tls_log_by_pid: HashMap<u64, (Box<[u8]>, u64)>,

    current_record_state: RecordState,
    rel_line_nr: u64,

    current_year: i64,
    current_month: i64,
    current_file_index: usize,

    count: u64,

    buffered_stdout: BufWriter<std::io::Stdout>,

    options: Options,

    start_tm: time::Tm,
    end_tm: time::Tm,

    ctime: time_t,
    string_match: bool,

    lines: u64,

    timezone_offset: time_t,
}

impl Parser {
    fn new() -> Result<Self, Error> {
        let ltime = Tm::now_local()?;

        Ok(Self {
            sentries: HashMap::new(),
            fentries: HashMap::new(),
            qentries: HashMap::new(),
            msgid_lookup: HashMap::new(),
            smtp_tls_log_by_pid: HashMap::new(),
            current_record_state: Default::default(),
            rel_line_nr: 0,
            current_year: (ltime.tm_year + 1900) as i64,
            current_month: ltime.tm_mon as i64,
            current_file_index: 0,
            count: 0,
            buffered_stdout: BufWriter::with_capacity(4 * 1024 * 1024, std::io::stdout()),
            options: Options::default(),
            start_tm: Tm::zero(),
            end_tm: Tm::zero(),
            ctime: 0,
            string_match: false,
            lines: 0,
            timezone_offset: ltime.tm_gmtoff,
        })
    }

    fn free_sentry(&mut self, sentry_pid: u64) {
        self.sentries.remove(&sentry_pid);
    }

    fn free_qentry(&mut self, qid: &[u8], se: Option<&mut SEntry>) {
        if let Some(qe) = self.qentries.get(qid) {
            if let Some(se) = se {
                se.delete_ref(qe);
            }
        }

        self.qentries.remove(qid);
    }

    fn free_fentry(&mut self, fentry_logid: &[u8]) {
        self.fentries.remove(fentry_logid);
    }

    fn parse_files(&mut self) -> Result<(), Error> {
        if !self.options.inputfile.is_empty() {
            if self.options.inputfile == "-" {
                // read from STDIN
                self.current_file_index = 0;
                let mut reader = BufReader::new(std::io::stdin());
                self.handle_input_by_line(&mut reader)?;
            } else if let Ok(file) = File::open(&self.options.inputfile) {
                // read from specified file
                self.current_file_index = 0;
                let mut reader = BufReader::new(file);
                self.handle_input_by_line(&mut reader)?;
            }
        } else {
            let filecount = self.count_files_in_time_range();
            for i in (0..filecount).rev() {
                if let Ok(file) = File::open(LOGFILES[i]) {
                    self.current_file_index = i;
                    if i > 1 {
                        let gzdecoder = read::GzDecoder::new(file);
                        let mut reader = BufReader::new(gzdecoder);
                        self.handle_input_by_line(&mut reader)?;
                    } else {
                        let mut reader = BufReader::new(file);
                        self.handle_input_by_line(&mut reader)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_input_by_line(&mut self, reader: &mut dyn BufRead) -> Result<(), Error> {
        let mut buffer = Vec::<u8>::with_capacity(4096);
        let mut prev_time = 0;
        loop {
            if self.options.limit > 0 && (self.count >= self.options.limit) {
                self.write_all_ok("STATUS: aborted by limit (too many hits)\n");
                self.buffered_stdout.flush()?;
                std::process::exit(0);
            }

            buffer.clear();
            let size = match reader.read_until(b'\n', &mut buffer) {
                Err(e) => return Err(e.into()),
                Ok(0) => return Ok(()),
                Ok(s) => s,
            };
            // size includes delimiter
            let line = &buffer[0..size - 1];
            let complete_line = line;

            let (time, line) = match parse_time(
                line,
                self.current_year,
                self.current_month,
                self.timezone_offset,
            ) {
                Some(t) => t,
                None => continue,
            };

            // relative line number within a single timestamp
            if time != prev_time {
                self.rel_line_nr = 0;
            } else {
                self.rel_line_nr += 1;
            }
            prev_time = time;

            // skip until we're in the specified time frame
            if time < self.options.start {
                continue;
            }
            // past the specified time frame, we're done, exit the loop
            if time > self.options.end {
                break;
            }

            self.lines += 1;

            let (host, service, pid, line) = match parse_host_service_pid(line) {
                Some((h, s, p, l)) => (h, s, p, l),
                None => continue,
            };

            self.ctime = time;

            self.current_record_state.host = host.into();
            self.current_record_state.service = service.into();
            self.current_record_state.pid = pid;
            self.current_record_state.timestamp = time;

            self.string_match = false;
            if !self.options.string_match.is_empty()
                && find_lowercase(complete_line, self.options.string_match.as_bytes()).is_some()
            {
                self.string_match = true;
            }

            // complete_line required for the logs
            if service == b"pmg-smtp-filter" {
                handle_pmg_smtp_filter_message(line, self, complete_line);
            } else if service == b"postfix/postscreen" {
                handle_postscreen_message(line, self, complete_line);
            } else if service == b"postfix/qmgr" {
                handle_qmgr_message(line, self, complete_line);
            } else if service == b"postfix/lmtp"
                || service == b"postfix/smtp"
                || service == b"postfix/local"
                || service == b"postfix/error"
            {
                handle_lmtp_message(line, self, complete_line);
            } else if service == b"postfix/smtpd" {
                handle_smtpd_message(line, self, complete_line);
            } else if service == b"postfix/cleanup" {
                handle_cleanup_message(line, self, complete_line);
            }
        }
        Ok(())
    }

    /// Returns the number of files to parse. Does not error out if it can't access any file
    /// (permission denied)
    fn count_files_in_time_range(&mut self) -> usize {
        let mut count = 0;
        let mut buffer = Vec::new();

        for (i, item) in LOGFILES.iter().enumerate() {
            count = i;
            if let Ok(file) = File::open(item) {
                self.current_file_index = i;
                buffer.clear();
                if i > 1 {
                    let gzdecoder = read::GzDecoder::new(file);
                    let mut reader = BufReader::new(gzdecoder);
                    // check the first line
                    if let Ok(size) = reader.read_until(b'\n', &mut buffer) {
                        if size == 0 {
                            return count;
                        }
                        if let Some((time, _)) = parse_time(
                            &buffer[0..size],
                            self.current_year,
                            self.current_month,
                            self.timezone_offset,
                        ) {
                            // found the earliest file in the time frame
                            if time < self.options.start {
                                break;
                            }
                        }
                    } else {
                        return count;
                    }
                } else {
                    let mut reader = BufReader::new(file);
                    if let Ok(size) = reader.read_until(b'\n', &mut buffer) {
                        if size == 0 {
                            return count;
                        }
                        if let Some((time, _)) = parse_time(
                            &buffer[0..size],
                            self.current_year,
                            self.current_month,
                            self.timezone_offset,
                        ) {
                            if time < self.options.start {
                                break;
                            }
                        }
                    } else {
                        return count;
                    }
                }
            } else {
                return count;
            }
        }

        count + 1
    }

    fn handle_args(&mut self, args: &mut pico_args::Arguments) -> Result<(), Error> {
        if let Some(inputfile) = args.opt_value_from_str(["-i", "--inputfile"])? {
            self.options.inputfile = inputfile;
        }

        if let Some(start) = args.opt_value_from_str::<_, String>(["-s", "--starttime"])? {
            if let Ok(res) = time::strptime(&start, c_str!("%F %T")) {
                self.options.start = res.as_utc_to_epoch();
                self.start_tm = res;
            } else if let Ok(res) = time::strptime(&start, c_str!("%s")) {
                self.options.start = res.as_utc_to_epoch();
                self.start_tm = res;
            } else {
                bail!("failed to parse start time");
            }
        } else {
            let mut ltime = Tm::now_local()?;
            ltime.tm_sec = 0;
            ltime.tm_min = 0;
            ltime.tm_hour = 0;
            self.options.start = ltime.as_utc_to_epoch();
            self.start_tm = ltime;
        }

        if let Some(end) = args.opt_value_from_str::<_, String>(["-e", "--endtime"])? {
            if let Ok(res) = time::strptime(&end, c_str!("%F %T")) {
                self.options.end = res.as_utc_to_epoch();
                self.end_tm = res;
            } else if let Ok(res) = time::strptime(&end, c_str!("%s")) {
                self.options.end = res.as_utc_to_epoch();
                self.end_tm = res;
            } else {
                bail!("failed to parse end time");
            }
        } else {
            self.options.end = unsafe { libc::time(std::ptr::null_mut()) };
            self.end_tm = Tm::at_local(self.options.end)?;
        }

        if self.options.end < self.options.start {
            bail!("end time before start time");
        }

        self.options.limit = match args.opt_value_from_str::<_, String>(["-l", "--limit"])? {
            Some(l) => l.parse().unwrap(),
            None => 0,
        };

        while let Some(q) = args.opt_value_from_str::<_, String>(["-q", "--queue-id"])? {
            let ltime: time_t = 0;
            let rel_line_nr: libc::c_ulong = 0;
            let input = CString::new(q.as_str())?;
            let bytes = concat!("T%08lXL%08lX", "\0");
            let format = unsafe { std::ffi::CStr::from_bytes_with_nul_unchecked(bytes.as_bytes()) };
            if unsafe { libc::sscanf(input.as_ptr(), format.as_ptr(), &ltime, &rel_line_nr) == 2 } {
                self.options
                    .match_list
                    .push(Match::RelLineNr(ltime, rel_line_nr));
            } else {
                self.options
                    .match_list
                    .push(Match::Qid(q.as_bytes().into()));
            }
        }

        if let Some(from) = args.opt_value_from_str(["-f", "--from"])? {
            self.options.from = from;
        }
        if let Some(to) = args.opt_value_from_str(["-t", "--to"])? {
            self.options.to = to;
        }
        if let Some(host) = args.opt_value_from_str(["-h", "--host"])? {
            self.options.host = host;
        }
        if let Some(msgid) = args.opt_value_from_str(["-m", "--msgid"])? {
            self.options.msgid = msgid;
        }

        self.options.exclude_greylist = args.contains(["-g", "--exclude-greylist"]);
        self.options.exclude_ndr = args.contains(["-n", "--exclude-ndr"]);

        while args.contains(["-v", "--verbose"]) {
            self.options.verbose += 1;
        }

        if let Some(string_match) = args.opt_value_from_str(["-x", "--search-string"])? {
            self.options.string_match = string_match;
        }

        Ok(())
    }

    fn write_all_ok<T: AsRef<[u8]>>(&mut self, data: T) {
        self.buffered_stdout
            .write_all(data.as_ref())
            .expect("failed to write to stdout");
    }
}

impl Drop for Parser {
    fn drop(&mut self) {
        let mut qentries = std::mem::take(&mut self.qentries);
        for q in qentries.values() {
            let smtpd = q.borrow().smtpd.clone();
            if let Some(s) = smtpd {
                q.borrow_mut().print(self, Some(&*s.borrow()));
            } else {
                q.borrow_mut().print(self, None);
            }
        }
        qentries.clear();
        let mut sentries = std::mem::take(&mut self.sentries);
        for s in sentries.values() {
            s.borrow_mut().print(self);
        }
        sentries.clear();
    }
}

#[derive(Debug, Default)]
struct Options {
    match_list: Vec<Match>,
    inputfile: String,
    string_match: String,
    host: String,
    msgid: String,
    from: String,
    to: String,
    start: time_t,
    end: time_t,
    limit: u64,
    verbose: u32,
    exclude_greylist: bool,
    exclude_ndr: bool,
}

#[derive(Debug)]
enum Match {
    Qid(Box<[u8]>),
    RelLineNr(time_t, u64),
}

#[derive(Debug, Default)]
struct RecordState {
    host: Box<[u8]>,
    service: Box<[u8]>,
    pid: u64,
    timestamp: time_t,
}

fn get_or_create_qentry(
    qentries: &mut HashMap<Box<[u8]>, Rc<RefCell<QEntry>>>,
    qid: &[u8],
) -> Rc<RefCell<QEntry>> {
    if let Some(qe) = qentries.get(qid) {
        Rc::clone(qe)
    } else {
        let qe = Rc::new(RefCell::new(QEntry::default()));
        qe.borrow_mut().qid = qid.into();
        qentries.insert(qid.into(), qe.clone());
        qe
    }
}

fn get_or_create_sentry(
    sentries: &mut HashMap<u64, Rc<RefCell<SEntry>>>,
    pid: u64,
    rel_line_nr: u64,
    timestamp: time_t,
) -> Rc<RefCell<SEntry>> {
    if let Some(se) = sentries.get(&pid) {
        Rc::clone(se)
    } else {
        let se = Rc::new(RefCell::new(SEntry::default()));
        se.borrow_mut().rel_line_nr = rel_line_nr;
        se.borrow_mut().timestamp = timestamp;
        sentries.insert(pid, se.clone());
        se
    }
}

fn get_or_create_fentry(
    fentries: &mut HashMap<Box<[u8]>, Rc<RefCell<FEntry>>>,
    qid: &[u8],
) -> Rc<RefCell<FEntry>> {
    if let Some(fe) = fentries.get(qid) {
        Rc::clone(fe)
    } else {
        let fe = Rc::new(RefCell::new(FEntry::default()));
        fe.borrow_mut().logid = qid.into();
        fentries.insert(qid.into(), fe.clone());
        fe
    }
}

const LOGFILES: [&str; 32] = [
    "/var/log/syslog",
    "/var/log/syslog.1",
    "/var/log/syslog.2.gz",
    "/var/log/syslog.3.gz",
    "/var/log/syslog.4.gz",
    "/var/log/syslog.5.gz",
    "/var/log/syslog.6.gz",
    "/var/log/syslog.7.gz",
    "/var/log/syslog.8.gz",
    "/var/log/syslog.9.gz",
    "/var/log/syslog.10.gz",
    "/var/log/syslog.11.gz",
    "/var/log/syslog.12.gz",
    "/var/log/syslog.13.gz",
    "/var/log/syslog.14.gz",
    "/var/log/syslog.15.gz",
    "/var/log/syslog.16.gz",
    "/var/log/syslog.17.gz",
    "/var/log/syslog.18.gz",
    "/var/log/syslog.19.gz",
    "/var/log/syslog.20.gz",
    "/var/log/syslog.21.gz",
    "/var/log/syslog.22.gz",
    "/var/log/syslog.23.gz",
    "/var/log/syslog.24.gz",
    "/var/log/syslog.25.gz",
    "/var/log/syslog.26.gz",
    "/var/log/syslog.27.gz",
    "/var/log/syslog.28.gz",
    "/var/log/syslog.29.gz",
    "/var/log/syslog.30.gz",
    "/var/log/syslog.31.gz",
];

/// Parse a QID ([A-Z]+). Returns a tuple of (qid, remaining_text) or None.
fn parse_qid(data: &[u8], max: usize) -> Option<(&[u8], &[u8])> {
    // to simplify limit max to data.len()
    let max = max.min(data.len());
    // take at most max, find the first non-hex-digit
    match data.iter().take(max).position(|b| !b.is_ascii_hexdigit()) {
        // if there were less than 5 return nothing
        // the QID always has at least 5 characters for the microseconds (see
        // http://www.postfix.org/postconf.5.html#enable_long_queue_ids)
        Some(n) if n < 5 => None,
        // otherwise split at the first non-hex-digit
        Some(n) => Some(data.split_at(n)),
        // or return 'max' length QID if no non-hex-digit is found
        None => Some(data.split_at(max)),
    }
}

/// Parse a number. Returns a tuple of (parsed_number, remaining_text) or None.
fn parse_number(data: &[u8], max_digits: usize) -> Option<(usize, &[u8])> {
    let max = max_digits.min(data.len());
    if max == 0 {
        return None;
    }

    match data.iter().take(max).position(|b| !b.is_ascii_digit()) {
        Some(n) if n == 0 => None,
        Some(n) => {
            let (number, data) = data.split_at(n);
            // number only contains ascii digits
            let number = unsafe { std::str::from_utf8_unchecked(number) }
                .parse::<usize>()
                .unwrap();
            Some((number, data))
        }
        None => {
            let (number, data) = data.split_at(max);
            // number only contains ascii digits
            let number = unsafe { std::str::from_utf8_unchecked(number) }
                .parse::<usize>()
                .unwrap();
            Some((number, data))
        }
    }
}

/// Parse time. Returns a tuple of (parsed_time, remaining_text) or None.
fn parse_time(
    data: &'_ [u8],
    cur_year: i64,
    cur_month: i64,
    timezone_offset: time_t,
) -> Option<(time_t, &'_ [u8])> {
    parse_time_with_year(data, timezone_offset)
        .or_else(|| parse_time_no_year(data, cur_year, cur_month))
}

fn parse_time_with_year(data: &'_ [u8], timezone_offset: time_t) -> Option<(time_t, &'_ [u8])> {
    let mut timestamp_buffer = [0u8; 25];

    let count = data.iter().take_while(|b| **b != b' ').count();
    if count != 27 && count != 32 {
        return None;
    }
    let (timestamp, data) = data.split_at(count);
    // remove whitespace
    let data = &data[1..];

    // microseconds: .123456 -> 7 bytes
    let microseconds_idx = timestamp.iter().take_while(|b| **b != b'.').count();

    // YYYY-MM-DDTHH:MM:SS
    let year_time = &timestamp[0..microseconds_idx];
    let year_time_len = year_time.len();
    // Z | +HH:MM | -HH:MM
    let timezone = &timestamp[microseconds_idx + 7..];
    let timezone_len = timezone.len();
    let timestamp_len = year_time_len + timezone_len;
    timestamp_buffer[0..year_time_len].copy_from_slice(year_time);
    timestamp_buffer[year_time_len..timestamp_len].copy_from_slice(timezone);

    match proxmox_time::parse_rfc3339(unsafe {
        std::str::from_utf8_unchecked(&timestamp_buffer[0..timestamp_len])
    }) {
        // TODO handle timezone offset in old code path instead
        Ok(ltime) => Some((ltime + timezone_offset, data)),
        Err(_err) => None,
    }
}

fn parse_time_no_year(data: &'_ [u8], cur_year: i64, cur_month: i64) -> Option<(time_t, &'_ [u8])> {
    if data.len() < 15 {
        return None;
    }

    let mon = match &data[0..3] {
        b"Jan" => 0,
        b"Feb" => 1,
        b"Mar" => 2,
        b"Apr" => 3,
        b"May" => 4,
        b"Jun" => 5,
        b"Jul" => 6,
        b"Aug" => 7,
        b"Sep" => 8,
        b"Oct" => 9,
        b"Nov" => 10,
        b"Dec" => 11,
        _ => return None,
    };
    let data = &data[3..];

    // assume smaller month now than in log line means yearwrap
    let mut year = if cur_month < mon {
        cur_year - 1
    } else {
        cur_year
    };

    let mut ltime: time_t = (year - 1970) * 365 + CAL_MTOD[mon as usize];

    // leap year considerations
    if mon <= 1 {
        year -= 1;
    }
    ltime += (year - 1968) / 4;
    ltime -= (year - 1900) / 100;
    ltime += (year - 1600) / 400;

    let whitespace_count = data.iter().take_while(|b| b.is_ascii_whitespace()).count();
    let data = &data[whitespace_count..];

    let (mday, data) = match parse_number(data, 2) {
        Some(t) => t,
        None => return None,
    };
    if mday == 0 {
        return None;
    }

    ltime += (mday - 1) as i64;

    if data.is_empty() {
        return None;
    }

    let data = &data[1..];

    let (hour, data) = match parse_number(data, 2) {
        Some(t) => t,
        None => return None,
    };

    ltime *= 24;
    ltime += hour as i64;

    if let Some(c) = data.iter().next() {
        if (*c as char) != ':' {
            return None;
        }
    } else {
        return None;
    }
    let data = &data[1..];

    let (min, data) = match parse_number(data, 2) {
        Some(t) => t,
        None => return None,
    };

    ltime *= 60;
    ltime += min as i64;

    if let Some(c) = data.iter().next() {
        if (*c as char) != ':' {
            return None;
        }
    } else {
        return None;
    }
    let data = &data[1..];

    let (sec, data) = match parse_number(data, 2) {
        Some(t) => t,
        None => return None,
    };

    ltime *= 60;
    ltime += sec as i64;

    let data = match data.len() {
        0 => &[],
        _ => &data[1..],
    };

    Some((ltime, data))
}

type ByteSlice<'a> = &'a [u8];
/// Parse Host, Service and PID at the beginning of data. Returns a tuple of (host, service, pid, remaining_text).
fn parse_host_service_pid(data: &[u8]) -> Option<(ByteSlice, ByteSlice, u64, ByteSlice)> {
    let host_count = data
        .iter()
        .take_while(|b| !(**b as char).is_ascii_whitespace())
        .count();
    let host = &data[0..host_count];
    let data = &data[host_count + 1..]; // whitespace after host

    let service_count = data
        .iter()
        .take_while(|b| {
            (**b as char).is_ascii_alphabetic() || (**b as char) == '/' || (**b as char) == '-'
        })
        .count();
    let service = &data[0..service_count];
    let data = &data[service_count..];
    if data.get(0) != Some(&b'[') {
        return None;
    }
    let data = &data[1..];

    let pid_count = data
        .iter()
        .take_while(|b| (**b as char).is_ascii_digit())
        .count();
    let pid = match unsafe { std::str::from_utf8_unchecked(&data[0..pid_count]) }.parse() {
        // all ascii digits so valid utf8
        Ok(p) => p,
        Err(_) => return None,
    };
    let data = &data[pid_count..];
    if !data.starts_with(b"]: ") {
        return None;
    }
    let data = &data[3..];

    Some((host, service, pid, data))
}

/// A find implementation for [u8]. Returns the index or None.
fn find<T: PartialOrd>(data: &[T], needle: &[T]) -> Option<usize> {
    data.windows(needle.len()).position(|d| d == needle)
}

/// A find implementation for [u8] that converts to lowercase before the comparison. Returns the
/// index or None.
fn find_lowercase(data: &[u8], needle: &[u8]) -> Option<usize> {
    let data = data.to_ascii_lowercase();
    let needle = needle.to_ascii_lowercase();
    data.windows(needle.len()).position(|d| d == &needle[..])
}
