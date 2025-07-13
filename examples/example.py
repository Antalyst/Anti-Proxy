import sys; sys.dont_write_bytecode = True # don't create __pycache__
import logging
from pyzkfp import ZKFP2
from time import sleep
from threading import Thread
import pymysql
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


class FingerprintScanner:
    def verify_user_from_db(self, scanned_template):
        conn = None
        try:
            conn = pymysql.connect(**self.db_config, cursorclass=pymysql.cursors.DictCursor)
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM users")
                results = cursor.fetchall()
                if not results:
                    print('No users found in database.')
                    return False

                if str(type(scanned_template)) == "<class 'System.Byte[]>":
                    scanned_template = bytes(scanned_template)
                    print(f"Converted scanned_template to bytes, new length: {len(scanned_template)}")

                for result in results:
                    stored_template = result['fingerprint_template']
                    if str(type(stored_template)) == "<class 'System.Byte[]>":
                        stored_template = bytes(stored_template)

                    # Skip invalid data
                    if not stored_template or not scanned_template:
                        continue

                    match_score = self.zkfp2.DBMatch(stored_template, scanned_template)
                    print(f"Checking user {result['username']} with score {match_score}")
                    if match_score > 0:
                        print(f"User {result['username']} verified with score {match_score}")
                        self.zkfp2.Light('green')
                        return True

                print("No matching fingerprint found.")
                self.zkfp2.Light('red', 1)
                return False
        except Exception as e:
            self.logger.error(f"Error verifying user: {e}")
            print(f"Error verifying user: {e}")
            return False
        finally:
            if conn:
                conn.close()

    def __init__(self):
        self.logger = logging.getLogger('fps')
        fh = logging.FileHandler('logs.log')
        fh.setLevel(logging.INFO)
        fh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(fh)

        self.templates = []

        self.initialize_zkfp2()

        self.capture = None
        self.register = False
        self.fid = 1

        self.keep_alive = True

        # MySQL connection config
        self.db_config = {
            'host': 'localhost',
            'user': 'root',
            'password': '',
            'db': 'db',
            'charset': 'utf8mb4'
        }

    def save_template_to_db(self, template_bytes):
        # Ensure template_bytes is bytes
        if not isinstance(template_bytes, (bytes, bytearray)):
            print(f"Error: fingerprint template is not bytes, type: {type(template_bytes)}, value: {template_bytes}")
            self.logger.error(f"Fingerprint template is not bytes, type: {type(template_bytes)}, value: {template_bytes}")
            return
        conn = None
        try:
            conn = pymysql.connect(**self.db_config)
            with conn.cursor() as cursor:
                username = input('Username: ')
                sql = """
                INSERT INTO users (username, fingerprint_template)
                VALUES (%s, %s)
                """
                cursor.execute(sql, (username, template_bytes))
            conn.commit()
            self.logger.info('Fingerprint template saved to users table.')
        except Exception as e:
            self.logger.error(f'Error saving to DB: {e}')
        finally:
            if conn:
                conn.close()


    def initialize_zkfp2(self):
        self.zkfp2 = ZKFP2()
        self.zkfp2.Init()
        self.logger.info(f"{(i := self.zkfp2.GetDeviceCount())} Devices found. Connecting to the first device.")
        self.zkfp2.OpenDevice(0)
        self.zkfp2.Light("green")


    def capture_handler(self):
        try:
            tmp, img = self.capture
            if self.mode == 'register':
                fid, score = self.zkfp2.DBIdentify(tmp)
                if fid:
                    self.logger.info(f"successfully identified the user: {fid}, Score: {score}")
                    self.zkfp2.Light('green')
                    self.capture = None
                    return
                if self.register == False:
                    self.register = input("Do you want to register a new user? [y/n]: ").lower() == 'y'
                if self.register:
                    if len(self.templates) < 3:
                        if not self.templates or self.zkfp2.DBMatch(self.templates[-1], tmp) > 0:
                            self.zkfp2.Light('green')
                            self.templates.append(tmp)
                            message = f"Finger {len(self.templates)} registered successfully! " + (f"{3-len(self.templates)} presses left." if 3-len(self.templates) > 0 else '')
                            self.logger.info(message)
                            if len(self.templates) == 3:
                                regTemp, regTempLen = self.zkfp2.DBMerge(*self.templates)
                                print(f"[DEBUG] regTemp type: {type(regTemp)}, length: {len(regTemp)}")
                                # Convert System.Byte[] to bytes if needed
                                if str(type(regTemp)) == "<class 'System.Byte[]'>":
                                    regTemp = bytes(regTemp)
                                    print(f"[DEBUG] regTemp converted to bytes, length: {len(regTemp)}")
                                self.save_template_to_db(regTemp)
                                self.templates.clear()
                                self.register = False
                                self.fid += 1
                        else:
                            self.zkfp2.Light('red', 1)
                            self.logger.warning("Different finger. Please enter the original finger!")
            elif self.mode == 'verify':
                self.verify_user_from_db(tmp)
        except KeyboardInterrupt:
            self.logger.info("Shutting down...")
            self.zkfp2.Terminate()
            exit(0)
        self.capture = None


    def _capture_handler(self):
        try:
            self.capture_handler()
        except Exception as e:
            self.logger.error(e)
            self.capture = None


    def listenToFingerprints(self):
        try:
            while self.keep_alive:
                capture = self.zkfp2.AcquireFingerprint()
                if capture and not self.capture:
                    self.capture = capture
                    Thread(target=self._capture_handler, daemon=True).start()
                sleep(0.1)
        except KeyboardInterrupt:
            self.logger.info("Shutting down...")
            self.zkfp2.Terminate()
            exit(0)


if __name__ == "__main__":
    print("Select mode:")
    print("1. Register user")
    print("2. Verify user")
    mode = input("Enter 1 or 2: ").strip()
    fingerprint_scanner = FingerprintScanner()
    if mode == '1':
        fingerprint_scanner.mode = 'register'
    elif mode == '2':
        fingerprint_scanner.mode = 'verify'
    else:
        print("Invalid mode selected.")
        exit(1)
    fingerprint_scanner.listenToFingerprints()
