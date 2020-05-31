//! Some structures about virtual interrupts.

use bit_set::BitSet;

/// The virtual interrupt controller to track pending interrupts
#[derive(Debug)]
pub struct InterruptController {
    num: usize,
    bitset: BitSet,
}

impl InterruptController {
    pub fn new(num: usize) -> Self {
        Self {
            num,
            bitset: BitSet::with_capacity(num),
        }
    }

    // In some architecture need to reverse the interrupt priority.
    #[inline(always)]
    fn vector(&self, vec: usize) -> usize {
        self.num - vec
    }

    /// Try to pop an interrupt with the given vector.
    pub fn try_pop(&mut self, vec: usize) -> bool {
        self.bitset.remove(self.vector(vec))
    }

    /// Pops the highest priority interrupt.
    pub fn pop(&mut self) -> Option<usize> {
        self.bitset.iter().next().map(|vec| {
            self.bitset.remove(vec);
            self.vector(vec)
        })
    }

    /// Clears all vectors except the given vector.
    pub fn clear_and_keep(&mut self, vec: usize) {
        let vec = self.vector(vec);
        let has = self.bitset.contains(vec);
        self.bitset.clear();
        if has {
            self.bitset.insert(vec);
        }
    }

    /// Tracks the given interrupt.
    pub fn virtual_interrupt(&mut self, vec: usize) {
        self.bitset.insert(self.vector(vec));
    }
}

/// A virtual timer to issue virtual time IRQ.
#[derive(Debug)]
pub struct VirtualTimer {
    last_tick: u64,
    current: u64,
    count: u64,
    pub irq_num: usize,
}

impl VirtualTimer {
    pub fn new() -> Self {
        Self {
            last_tick: 0,
            count: 0,
            current: 0,
            irq_num: 0,
        }
    }

    pub fn enabled(&self) -> bool {
        self.count > 0
    }

    pub fn enable(&mut self, irq_num: usize, count: u64, tick: u64) {
        self.last_tick = tick;
        self.irq_num = irq_num;
        self.set_count(count);
    }

    pub fn set_count(&mut self, count: u64) {
        self.current = 0;
        self.count = count;
    }

    pub fn tick(&mut self, tick: u64) -> bool {
        let elapsed = tick - self.last_tick;
        self.last_tick = tick;
        self.current += elapsed;
        if self.current >= self.count {
            self.current -= elapsed;
            true
        } else {
            false
        }
    }
}
