import commands
import time
import datetime
from haste_storage_client.core import HasteStorageClient
from keystoneauth1.identity import v3

auth = None

# Review: this file is too long. HIO related stuff should be its own library you can import anyway

def split_string(s):
    # Find last occurance of '}'
    # Review: what if part of the image data looks  like a } in ASCII?
    # Review: would it be better to use length-prefix based approach here?
    for i in range(len(s)):
        if s[i] == "}":
            index = i+1
            break

    # More secure to use pickle functions than call eval() on untrusted binary blob?
    return eval(s[0:index]), s[-(len(s)-index):]

# Review: since the process needs to be long running- suggest you wrap this function in a catch-all block, log+swallow all the exceptions, this way, the node won't 'crash' if there is an issue with one message
def extract_features(input):
    # Review - arn't we using python 3.x - use print()?
    print "Histogram function"

    # Discard bmp header # Review: see what you mean, but this comment is confusing
    from PIL import Image
    import io
    import numpy as np

    # Separate metadata and image and read image

    metadata, im = split_string(input)

    image = Image.open(io.BytesIO(im))

    # Calculate interesting measurements

    metadata['ImageSum'] = str(np.sum(image))

    # Review: This is slow, do it once on startup
    metadata['containerID'] = commands.getoutput('hostname')


    # Review, break up this into some smaller functions

    # Read useraneme and password for acces to SNIC
    # review: use JSON config based approach, mount it into the container. This will considerably simplify all this.
    u_name = str(metadata.get('username'))
    pwd = str(metadata.get('password'))
    expID = str(metadata.get('experimentID'))
    del metadata['username']
    del metadata['password']
    del metadata['experimentID']

    # Create a password auth plugin
    # See: https://docs.openstack.org/keystoneauth/latest/api/keystoneauth1.identity.v3.html#module-keystoneauth1.identity.v3.password
    global auth

    if auth is None:
        auth = v3.Password(auth_url='xxx',
                          username=u_name, 
                          password=pwd,
                          user_domain_name='xxx',
                          project_name='xxx',  # Haste
                          project_domain_name='xxx')


    # Review: we can read this directly  from the metadata using Lovisa's code.
    # Identifies both the experiment, and the session (ie. unique each time the stream starts),
    # for example, this would be a good format - this needs to be generated at the stream edge.
    stream_id = datetime.datetime.today().strftime('%Y_%m_%d__%H_%M_%S') + "_" + expID

    # Review: maintain a map to cache instances of the HasteStorageClient. HasteStorageClient will need to handle token renewal.
    client = HasteStorageClient(stream_id,
                                '130.xxx.yyy.zz',  # IP address of database server. # Review: this can come from config
                                27017,
                                auth)

    #blob = b'this is a binary blob eg. image data.'
    timestamp_cloud_edge = time.time()

    client.save(timestamp_cloud_edge,
                (12.34, 56.78), # Review: Spatial info should be read from simulator message.
                im,
                metadata)

    client.close()

# All this stuff should be in its own module

"""
Step 1: Check for dependency
"""
import pkgutil

s = pkgutil.find_loader('urllib3')
if not s:
    raise Exception("urllib3 module has not been installed.")

"""
Step 2: Import required modules
"""
import socket
import urllib3
import sys
import time
import os

"""
Step 3: Declare global variables
"""


class BatchErrorCode:
    SUCCESS = 0
    INVALID_PARAMETERS = 1
    OPEN_SOCKET_ERROR = 2
    DATA_SOCKET_ERROR = 3


class Setting(object):
    __node_name = None
    __node_data_port = None
    __node_addr = None
    __node_container_addr = None
    __master_addr = None
    __master_port = None
    __std_idle_time = None
    __token = "None"

    @staticmethod
    def set_params_from_env():
        Setting.__node_name = os.environ.get("HDE_NODE_NAME")
        Setting.__node_container_addr = Services.get_host_name_i()
        Setting.__node_addr = os.environ.get("HDE_NODE_ADDR")
        Setting.__node_port = int(os.environ.get("HDE_NODE_PORT"))
        Setting.__node_data_port = int(os.environ.get("HDE_NODE_DATA_PORT"))
        Setting.__master_addr = os.environ.get("HDE_MASTER_ADDR")
        Setting.__master_port = int(os.environ.get("HDE_MASTER_PORT"))
        Setting.__std_idle_time = int(os.environ.get("HDE_STD_IDLE_TIME"))
        Setting.__token = os.environ.get("HDE_TOKEN")



    @staticmethod
    def set_params(node_name, node_data_port, master_addr, master_port, std_idle_time, repo_addr, repo_port,
                   node_addr=None):
        Setting.__node_name = node_name
        Setting.__node_data_port = node_data_port
        Setting.__master_addr = master_addr
        Setting.__master_port = master_port
        Setting.__std_idle_time = std_idle_time
        Setting.__repo_addr = repo_addr
        Setting.__repo_port = repo_port
        # Get node container address from the environment
        Setting.__node_container_addr = os.environ.get("CONTAINER_ADDR")

        # Set node addr
        if node_addr:
            Setting.__node_addr = node_addr
        else:
            import socket
            Setting.__node_addr = socket.gethostname()

            # if addr is valid
            if Services.is_valid_ipv4(Setting.__node_addr) or Services.is_valid_ipv6(Setting.__node_addr):
                return None

            # if addr is not valid
            Setting.__node_addr = Services.get_host_name_i()
            if Services.is_valid_ipv4(Setting.__node_addr) or Services.is_valid_ipv6(Setting.__node_addr):
                return None

            print "Cannot get node ip address!"

    @staticmethod
    def get_node_name():
        return Setting.__node_name

    @staticmethod
    def get_node_data_port():
        return Setting.__node_data_port

    @staticmethod
    def get_node_port():
        return Setting.__node_port

    @staticmethod
    def get_node_container_addr():
        return Setting.__node_container_addr

    @staticmethod
    def get_node_addr():
        return Setting.__node_addr

    @staticmethod
    def get_master_addr():
        return Setting.__master_addr

    @staticmethod
    def get_master_port():
        return Setting.__master_port

    @staticmethod
    def get_std_idle_time():
        return Setting.__std_idle_time

    @staticmethod
    def get_token():
        return Setting.__token


"""
Batch Component -------------------------------------------------------------------------------------------------------
"""


class Services(object):
    @staticmethod
    def __get_str_pull_req():
        return "http://" + Setting.get_master_addr() + ":" + str(Setting.get_master_port()) + "/streamRequest?token=" + \
               Setting.get_token() + "&batch_addr=" + Setting.get_node_addr() + "&batch_port=" + \
               str(Setting.get_node_port()) + "&batch_status=0&c_name=" + Setting.get_node_name()

    @staticmethod
    def send_stream_request():
        http = urllib3.PoolManager()
        req_str = Services.__get_str_pull_req()

        def __send_req():
            r = http.request('POST', req_str)

            if r.status == 200:
                return True

            return False

        while not __send_req():
            print("Stream request from {0} to master fail! Retry now.".format(Setting.get_node_name()))

    @staticmethod
    def send_stream_request_data(content):
        http = urllib3.PoolManager()
        req_str = Services.__get_str_pull_req()

        def __send_req(content):
            r = http.request('POST', req_str)
            if r.status == 203:
                content += r.data
                return True

            if r.status == 200:
                return True

            return False

        while not __send_req(content):
            print("Stream request from {0} to master fail! Retry now.".format(Setting.get_node_name()))

    @staticmethod
    def get_host_name_i():
        import subprocess
        return subprocess.check_output(["hostname", "-I"]).decode('utf-8').strip()

    @staticmethod
    def is_valid_ipv4(ip):
        import re
        pattern = re.compile(r"""
                ^
                (?:
                  # Dotted variants:
                  (?:
                    # Decimal 1-255 (no leading 0's)
                    [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
                  |
                    0x0*[0-9a-f]{1,2}  # Hexadecimal 0x0 - 0xFF (possible leading 0's)
                  |
                    0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
                  )
                  (?:                  # Repeat 0-3 times, separated by a dot
                    \.
                    (?:
                      [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
                    |
                      0x0*[0-9a-f]{1,2}
                    |
                      0+[1-3]?[0-7]{0,2}
                    )
                  ){0,3}
                |
                  0x0*[0-9a-f]{1,8}    # Hexadecimal notation, 0x0 - 0xffffffff
                |
                  0+[0-3]?[0-7]{0,10}  # Octal notation, 0 - 037777777777
                |
                  # Decimal notation, 1-4294967295:
                  429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|
                  42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|
                  4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8}
                )
                $
            """, re.VERBOSE | re.IGNORECASE)
        return pattern.match(ip) is not None

    @staticmethod
    def is_valid_ipv6(ip):
        import re
        pattern = re.compile(r"""
                ^
                \s*                         # Leading whitespace
                (?!.*::.*::)                # Only a single whildcard allowed
                (?:(?!:)|:(?=:))            # Colon iff it would be part of a wildcard
                (?:                         # Repeat 6 times:
                    [0-9a-f]{0,4}           #   A group of at most four hexadecimal digits
                    (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
                ){6}                        #
                (?:                         # Either
                    [0-9a-f]{0,4}           #   Another group
                    (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
                    [0-9a-f]{0,4}           #   Last group
                    (?: (?<=::)             #   Colon iff preceeded by exacly one colon
                     |  (?<!:)              #
                     |  (?<=:) (?<!::) :    #
                     )                      # OR
                 |                          #   A v4 address with NO leading zeros
                    (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
                    (?: \.
                        (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
                    ){3}
                )
                \s*                         # Trailing whitespace
                $
            """, re.VERBOSE | re.IGNORECASE | re.DOTALL)
        return pattern.match(ip) is not None


"""
Entry point
"""

if __name__ == '__main__':

    # Check for parameter (port)
    """
    argvs = sys.argv[1:]
    if len(argvs) == 0:
        Services.print_help()
        exit(BatchErrorCode.INVALID_PARAMETERS)

    if argvs[0] == 0:
        print "Terminated by controller."
        exit(BatchErrorCode.SUCCESS)

    if argvs[0] == '--help' or argvs[0] == '-h':
        Services.print_help()
        exit(BatchErrorCode.SUCCESS)

    # Unpacking parameters
    try:
        Setting.set_params(argvs[0], int(argvs[1]), argvs[2], int(argvs[3]), int(argvs[4]), argvs[5], int(argvs[6]))
    except:
        print("Invalid Parameters!")
        exit(BatchErrorCode.INVALID_PARAMETERS)

    # Run the flow
    print "Batch " + Setting.get_node_name() + " opening socket on " + Setting.get_node_addr() + ":" + str(
        Setting.get_node_data_port())
    """
    Setting.set_params_from_env()

    s = None
    for res in socket.getaddrinfo(Setting.get_node_container_addr(), Setting.get_node_data_port(), socket.AF_UNSPEC,
                                  socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
        af, socktype, proto, canonname, sa = res
        try:
            s = socket.socket(af, socktype, proto)
        except socket.error as msg:
            s = None
            continue
        try:
            s.bind(sa)
            s.listen(1)
        except socket.error as msg:
            s.close()
            s = None
            continue
        break
    if s is None:
        print 'Open Socket Error'
        sys.exit(BatchErrorCode.OPEN_SOCKET_ERROR)

    try:
        while True:
            # Send a stream request to server
            time1 = time.time()
            data = bytearray()
            Services.send_stream_request_data(data)
            time2 = time3 = time.time()
            if len(data) == 0:
                # No data return from the system, waiting for stream.
                conn, addr = s.accept()
                print 'Streaming from ', addr[0], ":", addr[1]

                # Extracting object id
                # object_id = struct.unpack(">Q", conn.recv(8))[0]

                while 1:
                    content = conn.recv(2048)
                    if not content: break
                    data += content
                conn.close()
                time3 = time.time()

                # ret = pickle.loads(str(data))
            else:
                # Extracting object id
                # print 'Streaming from messaging system.'
                # object_id = struct.unpack(">Q", data[0:8])[0]

                # ret = pickle.loads(str(data[8:]))
                pass

            # print "[Time [ " + str(time2 - time1) + " : " + str(time3 - time2) + " ]"
            # print Setting.get_node_name() + " processing object " + str(object_id)
            # feature_list = []
            # for i, item in enumerate(ret.result):
            #     feature_list.append(Services.g2(item))

            """
            User-Code::::
            """
            extract_features(str(data))

            # encoder = zlib.compressobj()
            # compressed_feature = encoder.compress(pickle.dumps(feature_list)) + encoder.flush()

            # Services.push_feature_to_repo(compressed_feature, object_id)

    except IOError as e:
        print str(e)
        s.close()
        sys.exit(BatchErrorCode.DATA_SOCKET_ERROR)

    s.close()

    print "Terminated by controller."
    sys.exit(BatchErrorCode.SUCCESS)
