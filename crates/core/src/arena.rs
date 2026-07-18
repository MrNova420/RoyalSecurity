use std::alloc::{Layout, alloc, dealloc};
use std::cell::Cell;
use std::mem::align_of;

const DEFAULT_CAPACITY: usize = 1024 * 1024;

pub struct ArenaStats {
    pub allocations: usize,
    pub bytes_used: usize,
    pub capacity: usize,
}

struct BumpInner {
    buf: *mut u8,
    capacity: usize,
    offset: Cell<usize>,
    allocations: Cell<usize>,
}

unsafe impl Send for BumpInner {}
unsafe impl Sync for BumpInner {}

impl Drop for BumpInner {
    fn drop(&mut self) {
        unsafe {
            let layout = Layout::from_size_align_unchecked(self.capacity, align_of::<u8>());
            dealloc(self.buf, layout);
        }
    }
}

pub struct Arena {
    inner: BumpInner,
}

unsafe impl Send for Arena {}

impl Arena {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(align_of::<usize>());
        let layout = Layout::from_size_align(capacity, align_of::<usize>()).unwrap();
        let buf = unsafe { alloc(layout) };
        if buf.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        Self {
            inner: BumpInner {
                buf,
                capacity,
                offset: Cell::new(0),
                allocations: Cell::new(0),
            },
        }
    }

    pub fn alloc<T>(&self, val: T) -> &T {
        let size = std::mem::size_of::<T>();
        let align = align_of::<T>();
        let offset = self.inner.offset.get();
        let aligned = (offset + align - 1) & !(align - 1);
        let new_offset = aligned + size;
        if new_offset > self.inner.capacity {
            panic!("arena out of memory");
        }
        unsafe {
            let ptr = self.inner.buf.add(aligned) as *mut T;
            ptr.write(val);
            self.inner.offset.set(new_offset);
            self.inner.allocations.set(self.inner.allocations.get() + 1);
            &*ptr
        }
    }

    pub fn reset(&self) {
        self.inner.offset.set(0);
        self.inner.allocations.set(0);
    }

    pub fn stats(&self) -> ArenaStats {
        ArenaStats {
            allocations: self.inner.allocations.get(),
            bytes_used: self.inner.offset.get(),
            capacity: self.inner.capacity,
        }
    }

    pub fn bytes_remaining(&self) -> usize {
        self.inner.capacity - self.inner.offset.get()
    }
}

impl Default for Arena {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arena_new() {
        let arena = Arena::new(4096);
        let stats = arena.stats();
        assert_eq!(stats.capacity, 4096);
        assert_eq!(stats.bytes_used, 0);
        assert_eq!(stats.allocations, 0);
    }

    #[test]
    fn test_arena_alloc_primitives() {
        let arena = Arena::new(4096);
        let val = arena.alloc(42u64);
        assert_eq!(*val, 42);
        let val2 = arena.alloc(3.14f64);
        assert_eq!(*val2, 3.14);
        assert_eq!(arena.stats().allocations, 2);
        assert!(arena.stats().bytes_used > 0);
    }

    #[test]
    fn test_arena_alloc_struct() {
        let arena = Arena::new(4096);
        let val = arena.alloc(String::from("hello arena"));
        assert_eq!(val, "hello arena");
        assert_eq!(arena.stats().allocations, 1);
    }

    #[test]
    fn test_arena_reset() {
        let arena = Arena::new(4096);
        arena.alloc(1u32);
        arena.alloc(2u32);
        assert_eq!(arena.stats().allocations, 2);
        assert!(arena.stats().bytes_used > 0);
        arena.reset();
        let stats = arena.stats();
        assert_eq!(stats.allocations, 0);
        assert_eq!(stats.bytes_used, 0);
        let val = arena.alloc(99u32);
        assert_eq!(*val, 99);
        assert_eq!(arena.stats().allocations, 1);
    }

    #[test]
    fn test_arena_bytes_remaining() {
        let arena = Arena::new(1024);
        let before = arena.bytes_remaining();
        assert_eq!(before, 1024);
        arena.alloc([0u8; 256]);
        let after = arena.bytes_remaining();
        assert!(after < before);
    }

    #[test]
    fn test_arena_default_capacity() {
        let arena = Arena::default();
        assert_eq!(arena.stats().capacity, DEFAULT_CAPACITY);
    }

    #[test]
    fn test_arena_alignment() {
        let arena = Arena::new(4096);
        let _ = arena.alloc(1u8);
        let val = arena.alloc(0xDEAD_BEEF_u64);
        let addr = val as *const u64 as usize;
        assert_eq!(addr % align_of::<u64>(), 0);
    }

    #[test]
    #[should_panic(expected = "arena out of memory")]
    fn test_arena_overflow_panics() {
        let arena = Arena::new(8);
        arena.alloc([0u8; 9]);
    }

    #[test]
    fn test_arena_many_allocs() {
        let arena = Arena::new(4096);
        for i in 0..100 {
            let val = arena.alloc(i as u64);
            assert_eq!(*val, i as u64);
        }
        assert_eq!(arena.stats().allocations, 100);
    }

    #[test]
    fn test_arena_alloc_str_ref() {
        let arena = Arena::new(4096);
        let s = String::from("allocated string");
        let r = arena.alloc(s);
        assert_eq!(r.as_str(), "allocated string");
    }

    #[test]
    fn test_arena_vec_alloc() {
        let arena = Arena::new(4096);
        let vec = vec![1, 2, 3, 4, 5];
        let r = arena.alloc(vec);
        assert_eq!(r.as_slice(), &[1, 2, 3, 4, 5]);
    }
}
