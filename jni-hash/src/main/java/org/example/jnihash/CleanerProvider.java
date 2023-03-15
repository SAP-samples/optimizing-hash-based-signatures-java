package org.example.jnihash;

import io.netty.buffer.ByteBuf;

import java.lang.ref.Cleaner;

public class CleanerProvider {
    private static Cleaner cleaner;

    static Cleaner getCleaner() {
        if(cleaner == null){
            cleaner = Cleaner.create();
        }
        return cleaner;
    }

    static Runnable getByteBufCleaningRunnable(ByteBuf... byteBufs) {
        return () -> {
            for(ByteBuf byteBuf : byteBufs){
                byteBuf.release();
            }
        };
    }

    public static void registerByteBufs(Object obj, ByteBuf... byteBufs){
        getCleaner().register(obj, getByteBufCleaningRunnable(byteBufs));
    }
}
