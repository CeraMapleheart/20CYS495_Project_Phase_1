import schedule
import time

def schedule_backup(backup_function, source_path, exclusions, compression, schedule_time):
    schedule.every().day.at(schedule_time).do(backup_function, source_path, exclusions, compression)
    while True:
        schedule.run_pending()
        time.sleep(1)
