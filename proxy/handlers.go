package proxy

import (
	"log"
	"regexp"
	"sync"
	"crypto/rand"
    "encoding/hex"
    "strings"

	"github.com/etclabscore/open-etc-pool/rpc"
)

var (
	noncePattern  = regexp.MustCompile("^0x[0-9a-f]{16}$")
	hashPattern   = regexp.MustCompile("^0x[0-9a-f]{64}$")
	workerPattern = regexp.MustCompile("^[0-9a-zA-Z-_]{1,8}$")
	addressCache  = sync.Map{} // Concurrent address cache
)


func (s *ProxyServer) handleSubscribe(cs *Session, params []string) (interface{}, *ErrorReply) {
	cs.stratum_mode = true
	s.registerSession(cs)

	// Generate extranonce (2 random bytes → 4 hex chars)
	extranonceBytes := make([]byte, 2)
	_, err := rand.Read(extranonceBytes)
	if err != nil {
		return nil, &ErrorReply{Message: "failed to generate extranonce"}
	}
	cs.extranonce = hex.EncodeToString(extranonceBytes)

	cs.extranonce = ""

	// Generate random subscription ID (16 bytes → 32 hex chars)
	subIDBytes := make([]byte, 16)
	_, err = rand.Read(subIDBytes)
	if err != nil {
		return nil, &ErrorReply{Message: "failed to generate subscription ID"}
	}
	subID := hex.EncodeToString(subIDBytes)

	// Build Stratum result response
	result := []interface{}{
		[]interface{}{
			"mining.notify",
			subID,
			"EthereumStratum/1.0.0",
		},
		cs.extranonce,
	}

	return result, nil
}


func (s *ProxyServer) handleLoginRPC(cs *Session, params []string) (bool, *ErrorReply) {
	if len(params) == 0 {
		return false, &ErrorReply{Code: -1, Message: "Invalid params"}
	}

	login := params[0]

	cs.login = login
	s.registerSession(cs)
	log.Printf("Stratum miner connected %v@%v", login, cs.ip)
	return true, nil
}


func (s *ProxyServer) handleLoginRPCStratum(cs *Session, params []string) (bool, *ErrorReply) {
	if len(params) == 0 {
		return false, &ErrorReply{Code: -1, Message: "Invalid params"}
	}

	login := params[0]

	cs.login = login
	log.Printf("Stratum miner connected %v@%v", login, cs.ip)
	return true, nil
}



// Optimized work handler
func (s *ProxyServer) handleGetWorkRPC(cs *Session) ([]string, *ErrorReply) {
	t := s.currentBlockTemplate()
	if t == nil || len(t.Header) == 0 || s.isSick() {
		return nil, &ErrorReply{Code: 0, Message: "Work not ready"}
	}
	return []string{t.Header, t.Seed, s.diff}, nil
}

// Optimized submit handler with parallel validation
func (s *ProxyServer) handleTCPSubmitRPC(cs *Session, id string, params []string) (bool, *ErrorReply) {
	s.sessionsMu.RLock()
	_, ok := s.sessions[cs]
	s.sessionsMu.RUnlock()

	if !ok {
		return false, &ErrorReply{Code: 25, Message: "Not subscribed"}
	}

	// Fast validation
	if len(params) != 3 {
		s.policy.ApplyMalformedPolicy(cs.ip)
		return false, &ErrorReply{Code: -1, Message: "Invalid params"}
	}

	// Worker name processing
	if !workerPattern.MatchString(id) {
		id = "0"
	}

	// Parallel pattern validation
	var valid [3]bool
	var wg sync.WaitGroup
	wg.Add(3)

	validate := func(i int, pattern *regexp.Regexp, s string) {
		defer wg.Done()
		valid[i] = pattern.MatchString(s)
	}

	go validate(0, noncePattern, params[0])
	go validate(1, hashPattern, params[1])
	go validate(2, hashPattern, params[2])

	wg.Wait()

	if !valid[0] || !valid[1] || !valid[2] {
		s.policy.ApplyMalformedPolicy(cs.ip)
		return false, &ErrorReply{Code: -1, Message: "Malformed PoW result"}
	}

	t := s.currentBlockTemplate()
	exist, validShare := s.processShare(cs.login, id, cs.ip, t, params)
	ok = s.policy.ApplySharePolicy(cs.ip, !exist && validShare)

	if exist {
		return false, &ErrorReply{Code: 22, Message: "Duplicate share"}
	}

	if !validShare {
		if !ok {
			return false, &ErrorReply{Code: 23, Message: "Invalid share"}
		}
		return false, nil
	}

	if !ok {
		return true, &ErrorReply{Code: -1, Message: "High rate of invalid shares"}
	}
	return true, nil
}


func reverseHexBytes(s string) string {
    s = strings.TrimPrefix(s, "0x")
    if len(s)%2 != 0 {
        s = "0" + s
    }
    n := len(s)
    var rev strings.Builder
    for i := n; i > 0; i -= 2 {
        rev.WriteString(s[i-2:i])
    }
    return "0x" + rev.String()
}

func (s *ProxyServer) handleTCPSubmitRPCStratum(cs *Session, id string, params []string) (bool, *ErrorReply) {
	s.sessionsMu.RLock()
	_, ok := s.sessions[cs]
	s.sessionsMu.RUnlock()

	if !ok {
		// Not subscribed
		return false, &ErrorReply{Code: 25, Message: "Not subscribed"}
	}

	// Fast validation
	if len(params) != 3 {
		s.policy.ApplyMalformedPolicy(cs.ip)
		return false, &ErrorReply{Code: 20, Message: "Invalid params"}
	}

	// Worker name validation
	if !workerPattern.MatchString(id) {
		id = "0"
	}

	// Parallel pattern validation
	var valid [3]bool
	var wg sync.WaitGroup
	wg.Add(3)

	validate := func(i int, pattern *regexp.Regexp, s string) {
		defer wg.Done()
		valid[i] = pattern.MatchString(s)
	}

	go validate(0, noncePattern, params[0])
	go validate(1, hashPattern, params[1])
	go validate(2, hashPattern, params[2])

	//params[0] = reverseHexBytes(params[0])

	wg.Wait()

	if !valid[0] || !valid[1] || !valid[2] {
		s.policy.ApplyMalformedPolicy(cs.ip)
		return false, &ErrorReply{Code: 20, Message: "Malformed PoW result"}
	}

	t := s.currentBlockTemplate()

	exist, validShare := s.processShare(cs.login, id, cs.ip, t, params)
	ok = s.policy.ApplySharePolicy(cs.ip, !exist && validShare)

	// Duplicate share
	if exist {
		return false, &ErrorReply{Code: 22, Message: "Duplicate share"}
	}

	// Invalid share or low difficulty share
	if !validShare {
		return false, &ErrorReply{Code: 23, Message: "Low difficulty share"}
	}

	// High invalid rate policy violation
	if !ok {
		return true, &ErrorReply{Code: 23, Message: "High rate of invalid shares"}
	}

	return true, nil
}

// Optimized block handler
func (s *ProxyServer) handleGetBlockByNumberRPC() *rpc.GetBlockReplyPart {
	if t := s.currentBlockTemplate(); t != nil {
		return t.GetPendingBlockCache
	}
	return nil
}

func (s *ProxyServer) handleUnknownRPC(cs *Session, m string) *ErrorReply {
	s.policy.ApplyMalformedPolicy(cs.ip)
	return &ErrorReply{Code: -3, Message: "Method not found"}
}
