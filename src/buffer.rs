use std::future::Future;
use std::pin::Pin;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use crossbeam_queue::ArrayQueue;

pub fn channel<T>(cap: usize) -> (BufferSender<T>, BufferReceiver<T>) {
    let buf = Arc::new(Buffer {
        queue: ArrayQueue::new(cap),
        waker_ptr: Default::default(),
    });
    (BufferSender { buf: buf.clone() }, BufferReceiver { buf })
}

pub struct BufferSender<T> {
    buf: Arc<Buffer<T>>,
}
impl<T> Clone for BufferSender<T> {
    fn clone(&self) -> Self {
        Self {
            buf: self.buf.clone(),
        }
    }
}
impl<T> BufferSender<T> {
    pub fn send(&self, t: T) -> bool {
        self.buf.send(t)
    }
}
pub struct BufferReceiver<T> {
    buf: Arc<Buffer<T>>,
}
impl<T> BufferReceiver<T> {
    pub async fn recv(&self) -> Option<T> {
        Inner {
            buf: self.buf.clone(),
        }
        .await
    }
}

struct Buffer<T> {
    queue: ArrayQueue<T>,
    waker_ptr: AtomicPtr<Waker>,
}

impl<T> Buffer<T> {
    fn send(&self, t: T) -> bool {
        let x = self.queue.push(t).is_ok();
        let waker = self.waker_ptr.swap(null_mut(), Ordering::AcqRel);
        if !waker.is_null() {
            unsafe {
                Box::from_raw(waker).wake();
            }
        }
        x
    }
}
struct Inner<T> {
    buf: Arc<Buffer<T>>,
}
impl<T> Future for Inner<T> {
    type Output = Option<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(v) = self.buf.queue.pop() {
            return Poll::Ready(Some(v));
        }
        let waker = self.buf.waker_ptr.swap(
            Box::into_raw(Box::new(cx.waker().clone())),
            Ordering::AcqRel,
        );
        if !waker.is_null() {
            let old_waker = unsafe { Box::from_raw(waker) };
            let _ = old_waker.will_wake(cx.waker());
        }
        Poll::Pending
    }
}
