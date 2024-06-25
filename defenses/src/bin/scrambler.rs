// Scrambler -- regularizes packet timing within segments and randomizes their
// sizes.
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


// Machine #1 states
const NUM_STATES_M1: usize = 7;

const START_STATE_INDEX: usize = 0;
const BLOCK_STATE_INDEX: usize = 1;
const MIN_STATE_INDEX:   usize = 2;
const LEFT_STATE_INDEX:  usize = 3; // index of L_1
const RIGHT_STATE_INDEX: usize = 4; // index of R_1

// Machine #2 states
const NUM_STATES_M2: usize = 3;

const COUNT_LEFT_INDEX:  usize = 0;
const COUNT_RIGHT_INDEX: usize = 1;
const SIGNAL_INDEX:      usize = 2;

// Shared constants
const PACKET_SIZE: f64 = 1500.0;


fn main() {
    let args: Vec<String> = env::args().collect();
    assert!(args.len() == 5, "Usage: {} <send interval> <minimum count> <min trail> <max trail>", &args[0]);
    
    let interval: f64 = args[1].parse().expect("Invalid send interval");
    let min_count: f64 = args[2].parse().expect("Invalid minimum segment size");
    let min_trail: f64 = args[3].parse().expect("Invalid minimum trailing count");
    let max_trail: f64 = args[4].parse().expect("Invalid maximum trailing count");
    
    let machine1 = generate_machine_one(interval, min_count, min_trail, max_trail);
    println!("Machine 1: {} ({})\n", machine1, machine1.len());

    let machine2 = generate_machine_two(min_count);
    println!("Machine 2: {} ({})\n", machine2, machine2.len());
}


// Generate Machine #1 with the specified parameters.
fn generate_machine_one(interval: f64, min_count: f64, min_trail: f64, max_trail: f64) -> String {
    // States
    let mut states: Vec<State> = Vec::with_capacity(NUM_STATES_M1);
    states.push(generate_start_state());
    states.push(generate_block_state());

    states.push(generate_min_state(interval, min_count));

    states.push(generate_left_state(0, interval, min_trail, max_trail));
    states.push(generate_right_state(0, interval, min_trail, max_trail));

    states.push(generate_left_state(1, interval, min_trail / 4.0, max_trail / 4.0));
    states.push(generate_right_state(1, interval, min_trail / 4.0, max_trail / 4.0));

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

// Generate the START state for Machine #1.
fn generate_start_state() -> State {
    // NonPaddingSent --> BLOCK (100%)
    let mut nonpadding_sent: HashMap<usize, f64> = HashMap::new();
    nonpadding_sent.insert(BLOCK_STATE_INDEX, 1.0);
    
    // Transitions
    let mut transitions: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    transitions.insert(Event::NonPaddingSent, nonpadding_sent);
    
    // START state
    let mut state = State::new(transitions, NUM_STATES_M1);
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
        param1: 0.0,
        param2: 0.0,
        start: 0.0,
        max: 0.0,
    };
    
    return state;
}


// Generate the BLOCK state for Machine #1.
fn generate_block_state() -> State {
    // BlockingBegin --> MIN (100%)
    let mut blocking_begin: HashMap<usize, f64> = HashMap::new();
    blocking_begin.insert(MIN_STATE_INDEX, 1.0);
    
    // Transitions
    let mut transitions: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    transitions.insert(Event::BlockingBegin, blocking_begin);
    
    // BLOCK state
    let mut state = State::new(transitions, NUM_STATES_M1);
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


// Generate the MIN state for Machine #1.
fn generate_min_state(interval: f64, min_count: f64) -> State {
    // PaddingSent --> MIN (100%)
    let mut padding_sent: HashMap<usize, f64> = HashMap::new();
    padding_sent.insert(MIN_STATE_INDEX, 1.0);

    // LimitReached --> R_1 (100%)
    let mut limit_reached: HashMap<usize, f64> = HashMap::new();
    limit_reached.insert(RIGHT_STATE_INDEX, 1.0);

    // Transitions
    let mut transitions: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    transitions.insert(Event::PaddingSent, padding_sent);
    transitions.insert(Event::LimitReached, limit_reached);
    
    // MIN state
    let mut state = State::new(transitions, NUM_STATES_M1);
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

    state.limit = Dist {
        dist: DistType::Uniform,
        param1: min_count,
        param2: min_count,
        start: 0.0,
        max: 0.0,
    };
    
    return state;
}


// Generate an L state for Machine #1.
fn generate_left_state(index: usize, interval: f64, min_trail: f64, max_trail: f64) -> State {
    // PaddingSent --> L_{index} (100%)
    let mut padding_sent: HashMap<usize, f64> = HashMap::new();
    padding_sent.insert(LEFT_STATE_INDEX + 2 * index, 1.0);

    // NonPaddingSent --> R_{index} (100%)
    let mut nonpadding_sent: HashMap<usize, f64> = HashMap::new();
    nonpadding_sent.insert(RIGHT_STATE_INDEX + 2 * index, 1.0);

    // LimitReached --> START (100%)
    let mut limit_reached: HashMap<usize, f64> = HashMap::new();
    limit_reached.insert(START_STATE_INDEX, 1.0);

    // BlockingBegin --> L_2 (if L_1)
    let mut blocking_begin: HashMap<usize, f64> = HashMap::new();
    blocking_begin.insert(LEFT_STATE_INDEX + 2, 1.0);

    // Transitions
    let mut transitions: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    transitions.insert(Event::PaddingSent, padding_sent);
    transitions.insert(Event::NonPaddingSent, nonpadding_sent);
    transitions.insert(Event::LimitReached, limit_reached);
    if index == 0 {
        transitions.insert(Event::BlockingBegin, blocking_begin);
    }
    
    // L_{index} state
    let mut state = State::new(transitions, NUM_STATES_M1);
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

    state.limit = Dist {
        dist: DistType::Uniform,
        param1: min_trail,
        param2: max_trail,
        start: 0.0,
        max: 0.0,
    };
    
    return state;
}

// Generate an R state for Machine #1.
fn generate_right_state(index: usize, interval: f64, min_trail: f64, max_trail: f64) -> State {
    // PaddingSent --> R_{index} (100%)
    let mut padding_sent: HashMap<usize, f64> = HashMap::new();
    padding_sent.insert(RIGHT_STATE_INDEX + 2 * index, 1.0);

    // NonPaddingSent --> L_{index} (100%)
    let mut nonpadding_sent: HashMap<usize, f64> = HashMap::new();
    nonpadding_sent.insert(LEFT_STATE_INDEX + 2 * index, 1.0);

    // LimitReached --> START (100%)
    let mut limit_reached: HashMap<usize, f64> = HashMap::new();
    limit_reached.insert(START_STATE_INDEX, 1.0);

    // BlockingBegin --> R_2 (if R_1)
    let mut blocking_begin: HashMap<usize, f64> = HashMap::new();
    blocking_begin.insert(RIGHT_STATE_INDEX + 2, 1.0);

    // Transitions
    let mut transitions: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    transitions.insert(Event::PaddingSent, padding_sent);
    transitions.insert(Event::NonPaddingSent, nonpadding_sent);
    transitions.insert(Event::LimitReached, limit_reached);
    if index == 0 {
        transitions.insert(Event::BlockingBegin, blocking_begin);
    }
    
    // R_{index} state
    let mut state = State::new(transitions, NUM_STATES_M1);
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

    state.limit = Dist {
        dist: DistType::Uniform,
        param1: min_trail,
        param2: max_trail,
        start: 0.0,
        max: 0.0,
    };
    
    return state;
}


// Generate Machine #2 with the specified parameters.
fn generate_machine_two(min_count: f64) -> String {
    // States
    let mut states: Vec<State> = Vec::with_capacity(NUM_STATES_M2);
    states.push(generate_count_left_state(min_count));
    states.push(generate_count_right_state(min_count));
    states.push(generate_signal_state());

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


// Generate the L state for Machine #2.
fn generate_count_left_state(count: f64) -> State {
    // NonPaddingSent --> L (100%)
    let mut nonpadding_sent: HashMap<usize, f64> = HashMap::new();
    nonpadding_sent.insert(COUNT_LEFT_INDEX, 1.0);

    // BlockingBegin --> R (100%)
    let mut blocking_begin: HashMap<usize, f64> = HashMap::new();
    blocking_begin.insert(COUNT_RIGHT_INDEX, 1.0);

    // LimitReached --> SIGNAL (100%)
    let mut limit_reached: HashMap<usize, f64> = HashMap::new();
    limit_reached.insert(SIGNAL_INDEX, 1.0);
    
    // Transitions
    let mut transitions: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    transitions.insert(Event::NonPaddingSent, nonpadding_sent);
    transitions.insert(Event::BlockingBegin, blocking_begin);
    transitions.insert(Event::LimitReached, limit_reached);

    // L state
    let mut state = State::new(transitions, NUM_STATES_M2);
    state.action_is_block = true;
    state.bypass = true;
    
    state.timeout = Dist {
        dist: DistType::Uniform,
        param1: 0.0,
        param2: 0.0,
        start: 0.0,
        max: 0.0,
    };
    
    state.action = Dist {
        dist: DistType::Uniform,
        param1: 0.0,
        param2: 0.0,
        start: 0.0,
        max: 0.0,
    };
    
    state.limit = Dist {
        dist: DistType::Uniform,
        param1: count * 1.25,
        param2: count * 1.25,
        start: 0.0,
        max: 0.0,
    };

    return state;
}


// Generate the R state for Machine #2.
fn generate_count_right_state(count: f64) -> State {
    // NonPaddingSent --> R (100%)
    let mut nonpadding_sent: HashMap<usize, f64> = HashMap::new();
    nonpadding_sent.insert(COUNT_RIGHT_INDEX, 1.0);

    // BlockingBegin --> L (100%)
    let mut blocking_begin: HashMap<usize, f64> = HashMap::new();
    blocking_begin.insert(COUNT_LEFT_INDEX, 1.0);

    // LimitReached --> SIGNAL (100%)
    let mut limit_reached: HashMap<usize, f64> = HashMap::new();
    limit_reached.insert(SIGNAL_INDEX, 1.0);
    
    // Transitions
    let mut transitions: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    transitions.insert(Event::NonPaddingSent, nonpadding_sent);
    transitions.insert(Event::BlockingBegin, blocking_begin);
    transitions.insert(Event::LimitReached, limit_reached);
    
    // R state
    let mut state = State::new(transitions, NUM_STATES_M2);
    state.action_is_block = true;
    state.bypass = true;
    
    state.timeout = Dist {
        dist: DistType::Uniform,
        param1: 0.0,
        param2: 0.0,
        start: 0.0,
        max: 0.0,
    };
    
    state.action = Dist {
        dist: DistType::Uniform,
        param1: 0.0,
        param2: 0.0,
        start: 0.0,
        max: 0.0,
    };

    state.limit = Dist {
        dist: DistType::Uniform,
        param1: count * 1.25,
        param2: count * 1.25,
        start: 0.0,
        max: 0.0,
    };
    
    return state;
}


// Generate the SIGNAL for Machine #2.
fn generate_signal_state() -> State {
    // BlockingBegin --> R (100%)
    let mut blocking_begin: HashMap<usize, f64> = HashMap::new();
    blocking_begin.insert(COUNT_RIGHT_INDEX, 1.0);
    
    // Transitions
    let mut transitions: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    transitions.insert(Event::BlockingBegin, blocking_begin);

    // SIGNAL state
    let mut state = State::new(transitions, NUM_STATES_M2);
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
