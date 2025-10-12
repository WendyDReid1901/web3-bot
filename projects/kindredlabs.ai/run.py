from bot import *
# ap调度
from apscheduler.schedulers.blocking import BlockingScheduler

if __name__ == '__main__':
    config_path='projects/kindredlabs.ai/config.json'
    manager=KindredLabsBotManager(config_path)
    # 每天9点运行
    manager.run()
    scheduler = BlockingScheduler(
        timezone='Asia/Shanghai',
        job_defaults={
            'max_instances': 10,
            'misfire_grace_time': 600,
            'coalesce': True,

        }
    )
    scheduler.add_job(manager.run, 'cron', hour=9, minute=0) 