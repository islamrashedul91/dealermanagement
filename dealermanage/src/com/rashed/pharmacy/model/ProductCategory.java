package com.rashed.pharmacy.model;

public class ProductCategory {
	
	private String product_category_id;		
	private String product_category_name;	
	private String description;				
	private String created;					
	private String updated;
	
	public String getProduct_category_id() {
		return product_category_id;
	}
	public void setProduct_category_id(String product_category_id) {
		this.product_category_id = product_category_id;
	}
	public String getProduct_category_name() {
		return product_category_name;
	}
	public void setProduct_category_name(String product_category_name) {
		this.product_category_name = product_category_name;
	}
	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
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
	

}
