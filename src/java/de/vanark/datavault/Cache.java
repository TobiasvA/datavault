package de.vanark.datavault;
import java.lang.ref.SoftReference;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.DelayQueue;
import java.util.concurrent.Delayed;
import java.util.concurrent.TimeUnit;

public class Cache<K, V> {

    private final ConcurrentHashMap<K, SoftReference<V>> cache = new ConcurrentHashMap<>();
    private final DelayQueue<DelayedCacheObject<K, V>> cleaningUpQueue = new DelayQueue<>();

    public Cache() {
        Thread cleanerThread = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    DelayedCacheObject<K, V> delayedCacheObject = cleaningUpQueue.take();
                    K key = delayedCacheObject.getKey();
                    SoftReference<V> value = delayedCacheObject.getReference();
                    cache.remove(key, value);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        });
        cleanerThread.setDaemon(true);
        cleanerThread.start();
    }

    public void add(K key, V value, long periodInMillis) {
        if (key == null) {
            return;
        }
        if (value == null) {
            cache.remove(key);
        } else {
            long expiryTime = System.currentTimeMillis() + periodInMillis;
            SoftReference<V> reference = new SoftReference<>(value);
            cache.put(key, reference);
            cleaningUpQueue.put(new DelayedCacheObject<>(key, reference, expiryTime));
        }
    }

    public void remove(K key) {
        cache.remove(key);
    }

    public V get(K key) {
        return Optional.ofNullable(cache.get(key)).map(SoftReference::get).orElse(null);
    }

    public void clear() {
        cache.clear();
    }

    public long size() {
        return cache.size();
    }

    private static class DelayedCacheObject<K, V> implements Delayed {

        private final K key;
        private final SoftReference<V> reference;
        private final long expiryTime;

        public DelayedCacheObject(K key, SoftReference<V> reference, long expiryTime) {
            this.key = key;
            this.reference = reference;
            this.expiryTime = expiryTime;
        }

        @Override
        @SuppressWarnings("rawtypes")
        public int compareTo(Delayed o) {
            if (o instanceof DelayedCacheObject)
                return Long.compare(expiryTime, ((DelayedCacheObject) o).expiryTime);
            else
                return Long.compare(expiryTime, o.getDelay(TimeUnit.MILLISECONDS) + System.currentTimeMillis());
        }

        @Override
        public long getDelay(TimeUnit unit) {
            return unit.convert(expiryTime - System.currentTimeMillis(), TimeUnit.MILLISECONDS);
        }

        public K getKey() {
            return key;
        }

        public SoftReference<V> getReference() {
            return reference;
        }
    }
}