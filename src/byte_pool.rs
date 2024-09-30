use bytes::BytesMut;
use crossbeam_queue::ArrayQueue;
use rustp2p::pipe::SendPacket;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

#[derive(Clone)]
pub struct BufferPool<T> {
    queue: Arc<ArrayQueue<T>>,
}
impl<T> BufferPool<T> {
    pub fn new() -> Self {
        Self {
            queue: Arc::new(ArrayQueue::new(256)),
        }
    }
}
impl<T: Allocatable> BufferPool<T> {
    pub fn alloc(&self) -> Block<T> {
        if let Some(data) = self.queue.pop() {
            Block::new(self.queue.clone(), data)
        } else {
            Block::new(self.queue.clone(), T::alloc())
        }
    }
}

pub struct Block<T> {
    queue: Arc<ArrayQueue<T>>,
    data: std::mem::ManuallyDrop<T>,
}
impl<T> Block<T> {
    pub fn new(queue: Arc<ArrayQueue<T>>, data: T) -> Self {
        Self {
            queue,
            data: std::mem::ManuallyDrop::new(data),
        }
    }
}
impl<T> Drop for Block<T> {
    fn drop(&mut self) {
        let data = std::mem::ManuallyDrop::into_inner(unsafe { std::ptr::read(&self.data) });
        let _ = self.queue.push(data);
    }
}
impl<T> Deref for Block<T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &Self::Target {
        self.data.deref()
    }
}
impl<T> DerefMut for Block<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data.deref_mut()
    }
}

pub trait Allocatable {
    fn alloc() -> Self;
}

impl Allocatable for SendPacket {
    fn alloc() -> Self {
        SendPacket::with_capacity(2048)
    }
}
impl Allocatable for BytesMut {
    fn alloc() -> Self {
        BytesMut::with_capacity(2048)
    }
}
