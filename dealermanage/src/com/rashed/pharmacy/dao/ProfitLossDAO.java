package com.rashed.pharmacy.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.rashed.pharmacy.model.ProfitLoss;
import com.rashed.pharmacy.dao.ProductDAO;
import com.rashed.pharmacy.util.*;

public class ProfitLossDAO {
	
	private Connection con;
	private static Connection conn;
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
	// for decimal format [S]
	DecimalFormat df = new DecimalFormat("#.##");
	// for decimal format [S]
	
	public ProfitLossDAO(){
		//con  = DbUtil.getConnection();
	}
	
	
	public void save(ProfitLoss pl){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO profit_loss(profit_loss_id, sales_id, from_account_id, to_account_id, total_sales_amount, total_tp_price, profit_amount, profit_percent, loss_amount, loss_percent, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO profit_loss(profit_loss_id, sales_id, from_account_id, to_account_id, total_sales_amount, total_tp_price, profit_amount, profit_percent, loss_amount, loss_percent, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, pl.getProfit_loss_id());
			ps.setString(2, pl.getSales_id());
			ps.setString(3, pl.getFrom_account_id());
			ps.setString(4, pl.getTo_account_id());
			ps.setDouble(5, pl.getTotal_sales_amount());
			ps.setDouble(6, pl.getTotal_tp_price());
			ps.setDouble(7, pl.getProfit_amount());
			ps.setString(8, pl.getProfit_percent());
			ps.setDouble(9, pl.getLoss_amount());
			ps.setString(10, pl.getLoss_percent());
			ps.setString(11, pl.getCreated());
			ps.setString(12, pl.getUpdated());
			ps.setString(13, pl.getCreated_by());
			ps.setString(14, pl.getUpdated_by());
			
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
	
	public void delete(String profit_loss_id){
		try{
			//PreparedStatement ps = con.prepareStatement("DELETE FROM profit_loss WHERE profit_loss_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM profit_loss WHERE profit_loss_id=?");
			
			ps.setString(1, profit_loss_id);
			
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
	
	public void profitLossAmount(String sales_id, String from_account_id, double salesTotalAmount, String product_id, int intOrderQuantity, String strCurrentDateTime){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO profit_loss(profit_loss_id, sales_id, from_account_id, to_account_id, total_sales_amount, total_tp_price, profit_amount, profit_percent, loss_amount, loss_percent, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO profit_loss(profit_loss_id, sales_id, from_account_id, to_account_id, total_sales_amount, total_tp_price, profit_amount, profit_percent, loss_amount, loss_percent, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ProfitLossDAO plDao = new ProfitLossDAO();
			
			// for get the value from ProductDAO [S]
			ProductDAO pdao = new ProductDAO();
			double doubleTpPrice = pdao.getProductById(product_id).getTp_price();
			double doubleTotalTpPrice = doubleTpPrice * intOrderQuantity;
			double doubleProfitAmount = 0.00;
			double profitPercent = 0.00;
			double doubleLossAmount = 0.00;
			double lossPercent = 0.00;
			String strProfitPercent = "0";
			String strPLossPercent = "0";
			if(salesTotalAmount >= doubleTotalTpPrice){
				doubleProfitAmount = salesTotalAmount - doubleTotalTpPrice;
				profitPercent = (doubleProfitAmount * 100) / doubleTotalTpPrice;
				// for decimal format [S]
				profitPercent = Double.valueOf(df.format(profitPercent));
				// for decimal format [E]
				strProfitPercent = String.valueOf(profitPercent);
			} else if(doubleTotalTpPrice >= salesTotalAmount){
				doubleLossAmount = doubleTotalTpPrice - salesTotalAmount;
				lossPercent = (doubleLossAmount * 100) / doubleTotalTpPrice;
				// for decimal format [S]
				lossPercent = Double.valueOf(df.format(lossPercent));
				// for decimal format [E]
				strPLossPercent = String.valueOf(lossPercent);
			}
			
			
			ps.setString(1, plDao.getProfitLossID().getProfit_loss_id());
			ps.setString(2, sales_id);
			ps.setString(3, from_account_id);
			ps.setString(4, "");
			ps.setDouble(5, salesTotalAmount);
			ps.setDouble(6, doubleTotalTpPrice);
			if(salesTotalAmount >= doubleTotalTpPrice){
				ps.setDouble(7, doubleProfitAmount);
				ps.setString(8, strProfitPercent+" %");
				ps.setDouble(9, doubleLossAmount);
				ps.setString(10, strPLossPercent+" %");
			} else if(doubleTotalTpPrice >= salesTotalAmount){
				ps.setDouble(7, doubleProfitAmount);
				ps.setString(8, strProfitPercent+" %");
				ps.setDouble(9, doubleLossAmount);
				ps.setString(10, strPLossPercent+" %");
			}
			ps.setString(11, strCurrentDateTime);
			ps.setString(12, "");
			ps.setString(13, "");
			ps.setString(14, "");
			
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
	
	// based on requisition id and date time get one one product and its quantity and tp_price [S]
	//public void profitLossAmountAllProduct(String sales_id, String from_account_id, double salesTotalAmount, String product_id, int intOrderQuantity, String strCurrentDateTime){
	public void profitLossAmountAllProduct(String sales_id, String from_account_id, double salesTotalAmount, double productTotalTpPrice, String strCurrentDateTime){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO profit_loss(profit_loss_id, sales_id, from_account_id, to_account_id, total_sales_amount, total_tp_price, profit_amount, profit_percent, loss_amount, loss_percent, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO profit_loss(profit_loss_id, sales_id, from_account_id, to_account_id, total_sales_amount, total_tp_price, profit_amount, profit_percent, loss_amount, loss_percent, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ProfitLossDAO plDao = new ProfitLossDAO();
			
			// for get the value from ProductDAO [S]
			ProductDAO pdao = new ProductDAO();
			/*double doubleTpPrice = pdao.getProductById(product_id).getTp_price();
			double doubleTotalTpPrice = doubleTpPrice * intOrderQuantity;*/
			double doubleProfitAmount = 0.00;
			double profitPercent = 0.00;
			double doubleLossAmount = 0.00;
			double lossPercent = 0.00;
			String strProfitPercent = "0";
			String strPLossPercent = "0";
			if(salesTotalAmount >= productTotalTpPrice){
				//doubleProfitAmount = salesTotalAmount - productTotalTpPrice;
				doubleProfitAmount = Double.valueOf(df.format(salesTotalAmount - productTotalTpPrice));
				profitPercent = (doubleProfitAmount * 100) / productTotalTpPrice;
				// for decimal format [S]
				profitPercent = Double.valueOf(df.format(profitPercent));
				// for decimal format [E]
				strProfitPercent = String.valueOf(profitPercent);
			} else if(productTotalTpPrice >= salesTotalAmount){
				//doubleLossAmount = productTotalTpPrice - salesTotalAmount;
				doubleLossAmount = Double.valueOf(df.format(productTotalTpPrice - salesTotalAmount));
				lossPercent = (doubleLossAmount * 100) / productTotalTpPrice;
				// for decimal format [S]
				lossPercent = Double.valueOf(df.format(lossPercent));
				// for decimal format [E]
				strPLossPercent = String.valueOf(lossPercent);
			}
			
			
			ps.setString(1, plDao.getProfitLossID().getProfit_loss_id());
			ps.setString(2, sales_id);
			ps.setString(3, from_account_id);
			ps.setString(4, "");
			ps.setDouble(5, salesTotalAmount);
			ps.setDouble(6, productTotalTpPrice);
			if(salesTotalAmount >= productTotalTpPrice){
				ps.setDouble(7, doubleProfitAmount);
				ps.setString(8, strProfitPercent+" %");
				ps.setDouble(9, doubleLossAmount);
				ps.setString(10, strPLossPercent+" %");
			} else if(productTotalTpPrice >= salesTotalAmount){
				ps.setDouble(7, doubleProfitAmount);
				ps.setString(8, strProfitPercent+" %");
				ps.setDouble(9, doubleLossAmount);
				ps.setString(10, strPLossPercent+" %");
			}
			ps.setString(11, strCurrentDateTime);
			ps.setString(12, "");
			ps.setString(13, "");
			ps.setString(14, "");
			
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
	// based on requisition id and date time get one one product and its quantity and tp_price [E]
	
	public List<ProfitLoss> getAllProfitLoss(){
		List<ProfitLoss> list = new ArrayList<ProfitLoss>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT profit_loss_id, sales_id, from_account_id, to_account_id, total_sales_amount, total_tp_price, profit_amount, profit_percent, loss_amount, loss_percent, created, updated, created_by, updated_by FROM profit_loss");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT profit_loss_id, sales_id, from_account_id, to_account_id, total_sales_amount, total_tp_price, profit_amount, profit_percent, loss_amount, loss_percent, created, updated, created_by, updated_by FROM profit_loss");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				ProfitLoss pl = new ProfitLoss();				
				
				pl.setProfit_loss_id(rs.getString(1));
				pl.setSales_id(rs.getString(2));
				pl.setFrom_account_id(rs.getString(3));
				pl.setTo_account_id(rs.getString(4));
				pl.setTotal_sales_amount(rs.getDouble(5));
				pl.setTotal_tp_price(rs.getDouble(6));
				pl.setProfit_amount(rs.getDouble(7));
				pl.setProfit_percent(rs.getString(8));
				pl.setLoss_amount(rs.getDouble(9));
				pl.setLoss_percent(rs.getString(10));
				pl.setCreated(rs.getString(11));
				pl.setUpdated(rs.getString(12));
				pl.setCreated_by(rs.getString(13));
				pl.setUpdated_by(rs.getString(14));
				
				list.add(pl);				
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
	
	public ProfitLoss getProfitLossById(String profit_loss_id){
		ProfitLoss pl = new ProfitLoss();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT profit_loss_id, sales_id, from_account_id, to_account_id, total_sales_amount, total_tp_price, profit_amount, profit_percent, loss_amount, loss_percent, created, updated, created_by, updated_by FROM profit_loss where profit_loss_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT profit_loss_id, sales_id, from_account_id, to_account_id, total_sales_amount, total_tp_price, profit_amount, profit_percent, loss_amount, loss_percent, created, updated, created_by, updated_by FROM profit_loss where profit_loss_id=?");
			
			ps.setString(1, profit_loss_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				pl.setProfit_loss_id(rs.getString(1));
				pl.setSales_id(rs.getString(2));
				pl.setFrom_account_id(rs.getString(3));
				pl.setTo_account_id(rs.getString(4));
				pl.setTotal_sales_amount(rs.getDouble(5));
				pl.setTotal_tp_price(rs.getDouble(6));
				pl.setProfit_amount(rs.getDouble(7));
				pl.setProfit_percent(rs.getString(8));
				pl.setLoss_amount(rs.getDouble(9));
				pl.setLoss_percent(rs.getString(10));
				pl.setCreated(rs.getString(11));
				pl.setUpdated(rs.getString(12));
				pl.setCreated_by(rs.getString(13));
				pl.setUpdated_by(rs.getString(14));
				
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

		return pl;
	}
	
	// generated auto increment id during add [S]
	public ProfitLoss getProfitLossID(){
		ProfitLoss pl = new ProfitLoss();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT profit_loss_id FROM profit_loss");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT profit_loss_id FROM profit_loss");
			rs = ps.executeQuery();
			
			int profit_loss_id = 0;
			
			if(rs.next() == false) {
				profit_loss_id = 1000000000;
				profit_loss_id = profit_loss_id+1;
				pl.setProfit_loss_id("PFLS" + String.valueOf(profit_loss_id));
			} else {
				if(rs.last()) {
					String strProfitLoss = rs.getString("profit_loss_id");
					profit_loss_id = Integer.parseInt(strProfitLoss.replaceAll("[^0-9]", ""));
					profit_loss_id = profit_loss_id+1;
					pl.setProfit_loss_id("PFLS" + String.valueOf(profit_loss_id));
				}
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
		
		return pl;
	}
	// generated auto increment id during add [E]

}