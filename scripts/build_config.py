import os
import json
import uuid

from hpfeeds.add_user import create_user


def get_bool(bool_str):
    if bool_str.lower() == "true":
        return True
    return False


def main():
    print("Starting build_config.py")
    HPFEEDS_HOST = os.environ.get("HPFEEDS_HOST", "hpfeeds3")
    HPFEEDS_PORT = os.environ.get("HPFEEDS_PORT", "10000")
    IDENT = os.environ.get("IDENT", "hpfeeds-logger")
    SECRET = os.environ.get("SECRET", "")
    CHANNELS = os.environ.get("CHANNELS", "amun.events,conpot.events,thug.events,beeswarm.hive,dionaea.capture,dionaea.connections,thug.files,beeswarm.feeder,cuckoo.analysis,kippo.sessions,cowrie.sessions,glastopf.events,glastopf.files,mwbinary.dionaea.sensorunique,snort.alerts,wordpot.events,p0f.events,suricata.events,shockpot.events,elastichoney.events,rdphoney.sessions,uhp.events,elasticpot.events,spylex.events,big-hp.events,ssh-auth-logger.events,honeydb-agent.events")
    FORMATTER_NAME = os.environ.get("FORMATTER_NAME", "splunk")
    FILELOG_ENABLED = os.environ.get("FILELOG_ENABLED", "false")
    LOG_FILE = os.environ.get("LOG_FILE", "/var/log/hpfeeds-logger/chn-splunk.log")
    SYSLOG_ENABLED = os.environ.get("SYSLOG_ENABLED", "false")
    SYSLOG_HOST = os.environ.get("SYSLOG_HOST", "localhost")
    SYSLOG_PORT = os.environ.get("SYSLOG_PORT", "514")
    SYSLOG_FACILITY = os.environ.get("SYSLOG_FACILITY", "USER")
    MONGODB_HOST = os.environ.get("MONGODB_HOST", "mongodb")
    MONGODB_PORT = os.environ.get("MONGODB_PORT", "27017")
    ROTATION_STRATEGY = os.environ.get("ROTATION_STRATEGY", "size")
    ROTATION_SIZE_MAX = os.environ.get("ROTATION_SIZE_MAX", "100")
    ROTATION_TIME_MAX = os.environ.get("ROTATION_TIME_MAX", "24")
    ROTATION_TIME_UNIT = os.environ.get("ROTATION_TIME_UNIT", "h")

    config_template = open("/opt/hpfeeds-logger/logger.json.example", 'r')

    if SECRET:
        secret = SECRET
    else:
        secret = str(uuid.uuid4()).replace("-", "")

    channels = CHANNELS.split(",")

    # Configure hpfeeds settings
    config = json.loads(config_template.read())
    config['host'] = HPFEEDS_HOST
    config['port'] = int(HPFEEDS_PORT)
    config['ident'] = IDENT
    config['secret'] = secret
    config['channels'] = channels

    config['formatter_name'] = FORMATTER_NAME

    # Configure filelog settings
    config['filelog']['filelog_enabled'] = get_bool(FILELOG_ENABLED)
    config['filelog']['log_file'] = LOG_FILE
    config['filelog']['rotation_strategy'] = ROTATION_STRATEGY
    config['filelog']['rotation_size_max'] = int(ROTATION_SIZE_MAX)
    config['filelog']['rotation_time_max'] = int(ROTATION_TIME_MAX)
    config['filelog']['rotation_time_unit'] = ROTATION_TIME_UNIT

    # Configure syslog settings
    config['syslog']['syslog_enabled'] = get_bool(SYSLOG_ENABLED)
    config['syslog']['syslog_host'] = SYSLOG_HOST
    config['syslog']['syslog_port'] = int(SYSLOG_PORT)
    config['syslog']['syslog_facility'] = SYSLOG_FACILITY

    print("Writing config...")

    with open("/opt/hpfeeds-logger/logger.json", 'w') as config_file:
        config_file.write(json.dumps(config))

    create_user(host=MONGODB_HOST, port=int(MONGODB_PORT), owner="chn",
                ident=IDENT, secret=secret, publish="", subscribe=CHANNELS)


if __name__ == "__main__":
    main()
