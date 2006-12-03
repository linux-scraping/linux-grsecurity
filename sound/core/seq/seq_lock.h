#ifndef __SND_SEQ_LOCK_H
#define __SND_SEQ_LOCK_H

#include <linux/sched.h>

#if defined(CONFIG_SMP) || defined(CONFIG_SND_DEBUG)

typedef atomic_t snd_use_lock_t;

/* initialize lock */
#define snd_use_lock_init(lockp) atomic_set(lockp, 0)

/* increment lock */
#define snd_use_lock_use(lockp) atomic_inc(lockp)

/* release lock */
#define snd_use_lock_free(lockp) atomic_dec(lockp)

/* wait until all locks are released */
void snd_use_lock_sync_helper(snd_use_lock_t *lock, const char *file, int line);
#define snd_use_lock_sync(lockp) snd_use_lock_sync_helper(lockp, __BASE_FILE__, __LINE__)

#else /* SMP || CONFIG_SND_DEBUG */

typedef spinlock_t snd_use_lock_t;	/* dummy */
#define snd_use_lock_init(lockp) do {} while (0)
#define snd_use_lock_use(lockp) do {} while (0)
#define snd_use_lock_free(lockp) do {} while (0)
#define snd_use_lock_sync(lockp) do {} while (0)

#endif /* SMP || CONFIG_SND_DEBUG */

#endif /* __SND_SEQ_LOCK_H */
