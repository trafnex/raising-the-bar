// A minimal implementation of the constant-rate defense.
// Code from the paper: David Hasselquist, Ethan Witwer, August Carlson, Niklas
// Johansson, and Niklas Carlsson. "Raising the Bar: Improved Fingerprinting
// Attacks and Defenses for Video Streaming Traffic". Proceedings on Privacy
// Enhancing Technologies (PoPETs), volume 4, 2024.
// If you use this code in your work, please include a reference to the paper.

use std::env;
use std::f64::INFINITY;
use std::collections::HashMap;

use maybenot::{
machine::Machine,
event::Event,
state::State,
dist::{Dist, DistType}
};


const NUM_STATES: usize = 3;

const BLOCK_STATE_INDEX: usize = 1;
const CONST_STATE_INDEX: usize = 2;

const SEND_INTERVAL: f64 = 4000.0; // 3 Mbps (250 packets/sec)
const PACKET_SIZE: f64 = 1500.0;


fn main() {
    let args: Vec<String> = env::args().collect();
    assert!(args.len() == 1 || args.len() == 2, "Usage: {} [send interval = 4000.0]", &args[0]);
    
    let interval: f64;
    
    if args.len() == 1 {
        interval = SEND_INTERVAL; // default
    } else {
        interval = args[1].parse().expect("Invalid send interval");
    }
    
    let machine = generate_machine(interval);
    println!("Machine: {} ({})\n", machine, machine.len());
}


// Generate a constant-rate machine.
fn generate_machine(interval: f64) -> String {
    // States
    let mut states: Vec<State> = Vec::with_capacity(NUM_STATES);
    states.push(generate_start_state());
    states.push(generate_block_state());
    states.push(generate_const_state(interval));

    // Machine
    let machine = Machine {
        allowed_padding_bytes: 0,
        max_padding_frac: 0.0,
        allowed_blocked_microsec: 0,
        max_blocking_frac: 0.0,
        states: states,
        include_small_packets: false,
    };
    
    return machine.serialize();
}


// Generate the START state for a machine.
fn generate_start_state() -> State {
    // NonPaddingSent/NonPaddingRecv --> BLOCK (100%)
    let mut nonpadding_sent: HashMap<usize, f64> = HashMap::new();
    nonpadding_sent.insert(BLOCK_STATE_INDEX, 1.0);
    
    let mut nonpadding_recv: HashMap<usize, f64> = HashMap::new();
    nonpadding_recv.insert(BLOCK_STATE_INDEX, 1.0);

    // Transitions
    let mut transitions: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    transitions.insert(Event::NonPaddingSent, nonpadding_sent);
    transitions.insert(Event::NonPaddingRecv, nonpadding_recv);
    
    return State::new(transitions, NUM_STATES);
}


// Generate the BLOCK state for a machine.
fn generate_block_state() -> State {
    // BlockingBegin --> CONST (100%)
    let mut blocking_begin: HashMap<usize, f64> = HashMap::new();
    blocking_begin.insert(CONST_STATE_INDEX, 1.0);
    
    // Transitions
    let mut transitions: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    transitions.insert(Event::BlockingBegin, blocking_begin);
    
    // BLOCK state
    let mut state = State::new(transitions, NUM_STATES);
    state.action_is_block = true;
    state.bypass = true;
    state.replace = true;
    
    state.timeout = Dist {
        dist: DistType::Uniform,
        param1: 0.0,
        param2: 0.0,
        start: 0.0,
        max: 0.0,
    };
    
    state.action = Dist {
        dist: DistType::Uniform,
        param1: INFINITY,
        param2: INFINITY,
        start: 0.0,
        max: 0.0,
    };
    
    return state;
}


// Generate the CONST state for a machine.
fn generate_const_state(interval: f64) -> State {
    // PaddingSent --> CONST (100%)
    let mut padding_sent: HashMap<usize, f64> = HashMap::new();
    padding_sent.insert(CONST_STATE_INDEX, 1.0);

    // Transitions
    let mut transitions: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    transitions.insert(Event::PaddingSent, padding_sent);
    
    // CONST state
    let mut state = State::new(transitions, NUM_STATES);
    state.bypass = true;
    state.replace = true;

    state.timeout = Dist {
        dist: DistType::Uniform,
        param1: interval,
        param2: interval,
        start: 0.0,
        max: 0.0,
    };

    state.action = Dist {
        dist: DistType::Uniform,
        param1: PACKET_SIZE,
        param2: PACKET_SIZE,
        start: 0.0,
        max: 0.0,
    };
    
    return state;
}
