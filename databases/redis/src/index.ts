import 'server-only'
import Redis, { Redis as RedisInstance } from "ioredis";

interface SetValueOptions {
  expire: number;
}

interface Config {
  redis_url: string;
}

export class RedisClient {
  private static instance: RedisClient | null = null;
  private static redisClient: RedisInstance | null = null;

  public static getInstance(config: Config): RedisClient {
    if (!RedisClient.instance) {
      RedisClient.instance = new RedisClient();
      RedisClient.redisClient = new Redis(config.redis_url);
    }
    return RedisClient.instance;
  }

  private get client(): RedisInstance {
    if (!RedisClient.redisClient) throw "No redis url provided before trying to access redis"
    return RedisClient.redisClient;
  }

  public async getValue(key: string): Promise<string | null> {
    return this.client.get(key);
  }

  public async setValue(key: string, value: string, options: SetValueOptions = { expire: 60 * 60 }): Promise<unknown> {
    return this.client.setex(key, options.expire, value,);
  }

  public async deleteKey(key: string): Promise<number> {
    return this.client.del(key);
  }

  public async connect(): Promise<void> {
    await this.client.connect();
    console.log("Redis client connected");
  }
}