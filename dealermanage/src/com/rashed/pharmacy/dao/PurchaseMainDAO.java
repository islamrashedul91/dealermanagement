package com.rashed.pharmacy.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.rashed.pharmacy.model.Product;
import com.rashed.pharmacy.model.PurchaseMain;
import com.rashed.pharmacy.dao.RequisitionMultiDAO;
import com.rashed.pharmacy.dao.SalesProductDAO;
import com.rashed.pharmacy.dao.PurchaseProductDAO;
import com.rashed.pharmacy.util.*;

public class PurchaseMainDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	private SalesProductDAO spdao;
	
	private PurchaseProductDAO ppdao;
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public PurchaseMainDAO(){
		//con  = DbUtil.getConnection();
		spdao = new SalesProductDAO();
		
		ppdao = new PurchaseProductDAO();
	}
	
	//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
	
	public void save(PurchaseMain pm){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO purchase_main(purchase_id, purchase_type, date_time, owner_id, owner_name, mobile, needed_date_time, from_account_id, to_account_id, company_id, company_name, total_amount, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, pm.getPurchase_id());
			ps.setString(2, pm.getPurchase_type());
			ps.setString(3, pm.getDate_time());
			ps.setString(4, pm.getOwner_id());
			ps.setString(5, pm.getOwner_name());
			ps.setString(6, pm.getMobile());
			ps.setString(7, pm.getNeeded_date_time());
			ps.setString(8, pm.getFrom_account_id());
			ps.setString(9, pm.getTo_account_id());
			ps.setString(10, pm.getCompany_id());
			ps.setString(11, pm.getCompany_name());
			ps.setDouble(12, pm.getTotal_amount());
			ps.setString(13, pm.getOrder_status());
			ps.setString(14, pm.getDelivery_status());
			ps.setString(15, pm.getCreated());
			ps.setString(16, pm.getUpdated());
			ps.setString(17, pm.getCreated_by());
			ps.setString(18, pm.getUpdated_by());
			
			ps.executeUpdate();
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void delete(String purchase_id){
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM purchase_main WHERE purchase_id=?");
			
			ps.setString(1, purchase_id);
			
			ps.executeUpdate();
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void deleteByIdDateTime(String purchase_id, String date_time){
		PreparedStatement ps = null;
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM purchase_main WHERE purchase_id=? and date_time=?");
			
			ps.setString(1, purchase_id);
			ps.setString(2, date_time);
			
			ps.executeUpdate();
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void update(PurchaseMain pm){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE purchase_main set purchase_type=?, date_time=?, owner_id=?, owner_name=?, mobile=?, needed_date_time=?, from_account_id=?, to_account_id=?, company_id=?, company_name=?, total_amount=?, order_status=?, delivery_status=?, created=?, updated=?, created_by=?, updated_by=? where purchase_id=?");
			
			ps.setString(1, pm.getPurchase_type());
			ps.setString(2, pm.getDate_time());
			ps.setString(3, pm.getOwner_id());
			ps.setString(4, pm.getOwner_name());
			ps.setString(5, pm.getMobile());
			ps.setString(6, pm.getNeeded_date_time());
			ps.setString(7, pm.getFrom_account_id());
			ps.setString(8, pm.getTo_account_id());
			ps.setString(9, pm.getCompany_id());
			ps.setString(10, pm.getCompany_name());
			ps.setDouble(11, pm.getTotal_amount());
			ps.setString(12, pm.getOrder_status());
			ps.setString(13, pm.getDelivery_status());
			ps.setString(14, pm.getCreated());
			ps.setString(15, pm.getUpdated());
			ps.setString(16, pm.getCreated_by());
			ps.setString(17, pm.getUpdated_by());
			ps.setString(18, pm.getPurchase_id());
			
			ps.executeUpdate();		
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void cancel(String purchase_id){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE purchase_main set order_status=?, updated=? where purchase_id=?");
			
			ps.setString(1, "C");
			ps.setString(2, strDate);
			ps.setString(3, purchase_id);
			
			ps.executeUpdate();		
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void approve(String purchase_id){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE purchase_main set order_status=?, updated=? where purchase_id=?");
			
			ps.setString(1, "A");
			ps.setString(2, strDate);
			ps.setString(3, purchase_id);
			
			ps.executeUpdate();		
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void deliveryApprove(String purchase_id){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE purchase_main set delivery_status=?, updated=? where purchase_id=?");
			
			ps.setString(1, "D");
			ps.setString(2, strDate);
			ps.setString(3, purchase_id);
			
			ps.executeUpdate();		
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void deliveryReturn(String purchase_id){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE purchase_main set delivery_status=?, updated=? where purchase_id=?");
			
			ps.setString(1, "R");
			ps.setString(2, strDate);
			ps.setString(3, purchase_id);
			
			ps.executeUpdate();		
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public List<PurchaseMain> getAllPurchaseMain(){
		List<PurchaseMain> list = new ArrayList<PurchaseMain>();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_id, purchase_type, date_time, owner_id, owner_name, mobile, needed_date_time, from_account_id, to_account_id, company_id, company_name, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM purchase_main ORDER BY created DESC");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				PurchaseMain pm = new PurchaseMain();				
				
				pm.setPurchase_id(rs.getString(1));
				pm.setPurchase_type(rs.getString(2));
				pm.setDate_time(rs.getString(3));
				pm.setOwner_id(rs.getString(4));
				pm.setOwner_name(rs.getString(5));
				pm.setMobile(rs.getString(6));
				pm.setNeeded_date_time(rs.getString(7));
				pm.setFrom_account_id(rs.getString(8));
				pm.setTo_account_id(rs.getString(9));
				pm.setCompany_id(rs.getString(10));
				pm.setCompany_name(rs.getString(11));
				pm.setTotal_amount(rs.getDouble(12));
				pm.setOrder_status(rs.getString(13));
				pm.setDelivery_status(rs.getString(14));
				pm.setCreated(rs.getString(15));
				pm.setUpdated(rs.getString(16));
				pm.setCreated_by(rs.getString(17));
				pm.setUpdated_by(rs.getString(18));
			
				list.add(pm);				
			}
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
		
		return list;
	}
	
	public PurchaseMain getPurchaseMainById(String purchase_id){
		PurchaseMain pm = new PurchaseMain();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_id, purchase_type, date_time, owner_id, owner_name, mobile, needed_date_time, from_account_id, to_account_id, company_id, company_name, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM purchase_main where purchase_id=?");
			
			ps.setString(1, purchase_id);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				pm.setPurchase_id(rs.getString(1));
				pm.setPurchase_type(rs.getString(2));
				pm.setDate_time(rs.getString(3));
				pm.setOwner_id(rs.getString(4));
				pm.setOwner_name(rs.getString(5));
				pm.setMobile(rs.getString(6));
				pm.setNeeded_date_time(rs.getString(7));
				pm.setFrom_account_id(rs.getString(8));
				pm.setTo_account_id(rs.getString(9));
				pm.setCompany_id(rs.getString(10));
				pm.setCompany_name(rs.getString(11));
				pm.setTotal_amount(rs.getDouble(12));
				pm.setOrder_status(rs.getString(13));
				pm.setDelivery_status(rs.getString(14));
				pm.setCreated(rs.getString(15));
				pm.setUpdated(rs.getString(16));
				pm.setCreated_by(rs.getString(17));
				pm.setUpdated_by(rs.getString(18));
				
			}
		} catch (Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}

		return pm;
	}
	
	public PurchaseMain getPurchaseMainByIdDateTime(String purchase_id, String date_time){
		PurchaseMain pm = new PurchaseMain();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_id, purchase_type, date_time, owner_id, owner_name, mobile, needed_date_time, from_account_id, to_account_id, company_id, company_name, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM purchase_main where purchase_id=? and date_time=?");
			
			ps.setString(1, purchase_id);
			ps.setString(2, date_time);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				pm.setPurchase_id(rs.getString(1));
				pm.setPurchase_type(rs.getString(2));
				pm.setDate_time(rs.getString(3));
				pm.setOwner_id(rs.getString(4));
				pm.setOwner_name(rs.getString(5));
				pm.setMobile(rs.getString(6));
				pm.setNeeded_date_time(rs.getString(7));
				pm.setFrom_account_id(rs.getString(8));
				pm.setTo_account_id(rs.getString(9));
				pm.setCompany_id(rs.getString(10));
				pm.setCompany_name(rs.getString(11));
				pm.setTotal_amount(rs.getDouble(12));
				pm.setOrder_status(rs.getString(13));
				pm.setDelivery_status(rs.getString(14));
				pm.setCreated(rs.getString(15));
				pm.setUpdated(rs.getString(16));
				pm.setCreated_by(rs.getString(17));
				pm.setUpdated_by(rs.getString(18));
				
			}
		} catch (Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}

		return pm;
	}
	
	// generated auto increment id during add [S]
	public PurchaseMain getPurchaseMainID(){
		PurchaseMain pm = new PurchaseMain();
		// for get deleted id [S]
		PreparedStatement ps2 = null;
		ResultSet rs2 = null;
		// for get deleted id [E]
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_id FROM purchase_main");
			
			rs = ps.executeQuery();
			
			int purchase_id = 0;
			// for get deleted id [S]
			/*if(rs.next() == false) {
				purchase_id = 1000000000;
				purchase_id = purchase_id+1;
				pm.setPurchase_id("PRCH" + String.valueOf(purchase_id));
			} else {
				if(rs.last()) {
					String strPurchaseMain = rs.getString("purchase_id");
					purchase_id = Integer.parseInt(strPurchaseMain.replaceAll("[^0-9]", ""));
					purchase_id = purchase_id+1;
					pm.setPurchase_id("PRCH" + String.valueOf(purchase_id));
				}
			}*/
			int purchase_id2 = 0;
			ps2 = con.prepareStatement("SELECT purchase_id FROM transaction_main");
			rs2 = ps2.executeQuery();
			
			if (rs.last()) {
				String strPurchaseMain = rs.getString("purchase_id");
				purchase_id = Integer.parseInt(strPurchaseMain.replaceAll("[^0-9]", ""));
			} 
			if (rs2.last()) {
				String strPurchaseMain2 = rs2.getString("purchase_id");
				purchase_id2 = Integer.parseInt(strPurchaseMain2.replaceAll("[^0-9]", ""));
			}
			
			if((purchase_id == 0) && (purchase_id2 == 0)){
			
				purchase_id = 1000000000;
				purchase_id = purchase_id+1;
				pm.setPurchase_id("PRCH" + String.valueOf(purchase_id));
			
			} else if (purchase_id > purchase_id2) {
				String strPurchaseMain = rs.getString("purchase_id");
				purchase_id = Integer.parseInt(strPurchaseMain.replaceAll("[^0-9]", ""));
				purchase_id = purchase_id+1;
				pm.setPurchase_id("PRCH" + String.valueOf(purchase_id));
			} else if (purchase_id2 > purchase_id) {
				String strPurchaseMain2 = rs2.getString("purchase_id");
				purchase_id = Integer.parseInt(strPurchaseMain2.replaceAll("[^0-9]", ""));
				purchase_id = purchase_id+1;
				pm.setPurchase_id("PRCH" + String.valueOf(purchase_id));
			} 
			// for get deleted id [E]
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps2 != null){
				try {
					ps2.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs2 != null){
				try {
					rs2.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
		
		return pm;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public PurchaseMain getSelectedOtherID(String purchase_id){
		PurchaseMain pm = new PurchaseMain();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_id, purchase_type, date_time, owner_id, company_id, order_status, delivery_status, total_amount, from_account_id, to_account_id FROM purchase_main WHERE purchase_id=?");
			
			ps.setString(1, purchase_id);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strPurchaseMain = rs.getString("purchase_id");
				String strPurchaseType = rs.getString("purchase_type");
				String strDateTime = rs.getString("date_time");
				String strOwner = rs.getString("owner_id");
				String strCompany = rs.getString("company_id");
				double dubleTotalAmount = rs.getDouble("total_amount");
				String strFromAccount = rs.getString("from_account_id");
				String strToAccount = rs.getString("to_account_id");
				String strOrderStatus = rs.getString("order_status");
				String strDeliveryStatus = rs.getString("delivery_status");
				
				pm.setPurchase_id(strPurchaseMain);
				pm.setPurchase_type(strPurchaseType);
				pm.setDate_time(strDateTime);
				pm.setOwner_id(strOwner);
				pm.setCompany_id(strCompany);
				pm.setTotal_amount(dubleTotalAmount);
				pm.setFrom_account_id(strFromAccount);
				pm.setTo_account_id(strToAccount);
				pm.setOrder_status(strOrderStatus);
				pm.setDelivery_status(strDeliveryStatus);
				
			}
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
		
		return pm;
	}
	// selected other respective id during update [E]
	
	// for insert into purchase_main total_amount from Purchase Product sum total amount [S]
	public void sumTotalAmountPP(String purchase_id, String date_time){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE purchase_main set total_amount=?, updated=? where purchase_id=? and date_time=?");
			
			ps.setDouble(1, ppdao.sumTotalAmount(purchase_id, date_time).getTotal_amount());
			ps.setString(2, strDate);
			ps.setString(3, purchase_id);
			ps.setString(4, date_time);
			
			ps.executeUpdate();		
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	// for insert into purchase_main total_amount from Purchase Product sum total amount [E]

}
