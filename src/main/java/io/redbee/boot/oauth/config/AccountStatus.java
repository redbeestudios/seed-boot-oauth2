package io.redbee.boot.oauth.config;

public enum AccountStatus {

	Valid(0),
	Blocked(1),
	Terminated(2);
	
	Integer value;
	
	AccountStatus (Integer val) {
		value = val;
	}
	
	public Integer getValue(){
		return value;
	}
}
