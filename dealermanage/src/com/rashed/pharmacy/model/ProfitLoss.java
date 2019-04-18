package com.rashed.pharmacy.model;

public class ProfitLoss {
	
	private String profit_loss_id;		
	private String sales_id;			
	private String from_account_id;		
	private String to_account_id;		
	private double total_sales_amount;	
	private double total_tp_price;		
	private double profit_amount;		
	private String profit_percent;	    
	private double loss_amount;			
	private String loss_percent;	    
	private String created;				
	private String updated;							
	private String created_by;			
	private String updated_by;
	
	public String getProfit_loss_id() {
		return profit_loss_id;
	}
	public void setProfit_loss_id(String profit_loss_id) {
		this.profit_loss_id = profit_loss_id;
	}
	public String getSales_id() {
		return sales_id;
	}
	public void setSales_id(String sales_id) {
		this.sales_id = sales_id;
	}
	public String getFrom_account_id() {
		return from_account_id;
	}
	public void setFrom_account_id(String from_account_id) {
		this.from_account_id = from_account_id;
	}
	public String getTo_account_id() {
		return to_account_id;
	}
	public void setTo_account_id(String to_account_id) {
		this.to_account_id = to_account_id;
	}
	public double getTotal_sales_amount() {
		return total_sales_amount;
	}
	public void setTotal_sales_amount(double total_sales_amount) {
		this.total_sales_amount = total_sales_amount;
	}
	public double getTotal_tp_price() {
		return total_tp_price;
	}
	public void setTotal_tp_price(double total_tp_price) {
		this.total_tp_price = total_tp_price;
	}
	public double getProfit_amount() {
		return profit_amount;
	}
	public void setProfit_amount(double profit_amount) {
		this.profit_amount = profit_amount;
	}
	public String getProfit_percent() {
		return profit_percent;
	}
	public void setProfit_percent(String profit_percent) {
		this.profit_percent = profit_percent;
	}
	public double getLoss_amount() {
		return loss_amount;
	}
	public void setLoss_amount(double loss_amount) {
		this.loss_amount = loss_amount;
	}
	public String getLoss_percent() {
		return loss_percent;
	}
	public void setLoss_percent(String loss_percent) {
		this.loss_percent = loss_percent;
	}
	public String getCreated() {
		return created;
	}
	public void setCreated(String created) {
		this.created = created;
	}
	public String getUpdated() {
		return updated;
	}
	public void setUpdated(String updated) {
		this.updated = updated;
	}
	public String getCreated_by() {
		return created_by;
	}
	public void setCreated_by(String created_by) {
		this.created_by = created_by;
	}
	public String getUpdated_by() {
		return updated_by;
	}
	public void setUpdated_by(String updated_by) {
		this.updated_by = updated_by;
	}

}
