from pyspark.sql import SparkSession
import math
import time

log4j_config_path = "log4j.properties"

spark = SparkSession.builder \
    .appName("Anticheat") \
    .config("spark.driver.extraJavaOptions",
            "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true -Dlog4j.configuration=file:" + log4j_config_path) \
    .config("spark.executor.extraJavaOptions",
            "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true -Dlog4j.configuration=file:" + log4j_config_path) \
    .getOrCreate()

logger = spark._jvm.org.apache.log4j.LogManager.getLogger("Anticheat")

def log_action(user_id, action):
    logger.info(f"User: {user_id} - {action}")


user_states = {}

# Anti-cheat thresholds
MAX_SPEED = 1000  # Max units per second

def analyze_movement(user_id, new_x, new_y, new_angle):

    global user_states

    # Initialize user state if not present
    if user_id not in user_states:
        user_states[user_id] = {
            'last_x': new_x,
            'last_y': new_y,
            'last_time': time.time(),
            'violations': 0,
        }

    user_state = user_states[user_id]
    last_x = user_state['last_x']
    last_y = user_state['last_y']
    last_time = user_state['last_time']

    # Calculate distance and time elapsed
    distance = math.sqrt((new_x - last_x)**2 + (new_y - last_y)**2)
    time_elapsed = time.time() - last_time
    speed = distance / time_elapsed if time_elapsed > 0 else 0

    # Check for speed violations
    if speed > MAX_SPEED:
        return True

    # Update the user state
    user_states[user_id].update({
        'last_x': new_x,
        'last_y': new_y,
        'last_time': time.time(),
    })

    return False