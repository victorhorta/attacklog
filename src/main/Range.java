package main;

import java.util.Date;
import java.sql.Timestamp;
import java.util.List;

public class Range {
	static int interval = 30;
	public Date initialTime;
	public Date finalTime;
	public int count=0;
	
	public Range(Date initialTime2){
		this.initialTime = initialTime2;
		//System.out.println(initialTime2.getTime());
		finalTime = new Date(initialTime2.getTime());
		finalTime.setSeconds(finalTime.getSeconds() + interval);
		//System.out.println(initialTime.toLocaleString());
		//System.out.println(finalTime.toLocaleString());
		//System.out.println("inicial "+ initialTime.toLocaleString() + " final " + finalTime.toLocaleString());
	}
	void countSyn(List<Timestamp> log){
		for(int i = 0 ; i < log.size();i++){
			Timestamp time = log.get(i);
			if(time.after(initialTime) && time.before(finalTime)){
				count ++;
			}
		}
		//System.out.println(count);
	}
	
}
