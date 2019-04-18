package com.rashed.pharmacy.model;

public class PackPiceces {
	
	private String pack_piceces_id;	
	private String pack_type;		
	private String pack_size;		
	private int piceces;			
	private String created;			
	private String updated;
	
	public String getPack_piceces_id() {
		return pack_piceces_id;
	}
	public void setPack_piceces_id(String pack_piceces_id) {
		this.pack_piceces_id = pack_piceces_id;
	}
	public String getPack_type() {
		return pack_type;
	}
	public void setPack_type(String pack_type) {
		this.pack_type = pack_type;
	}
	public String getPack_size() {
		return pack_size;
	}
	public void setPack_size(String pack_size) {
		this.pack_size = pack_size;
	}
	public int getPiceces() {
		return piceces;
	}
	public void setPiceces(int piceces) {
		this.piceces = piceces;
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
