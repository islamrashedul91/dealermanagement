package com.rashed.pharmacy.controller;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.google.zxing.WriterException;
import com.rashed.pharmacy.model.Purchase;
import com.rashed.pharmacy.dao.AccountDAO;
import com.rashed.pharmacy.dao.DayWiseAccountBalanceDAO;
import com.rashed.pharmacy.dao.PurchaseDAO;
import com.rashed.pharmacy.model.Product;
import com.rashed.pharmacy.dao.ProductDAO;
import com.rashed.pharmacy.model.CustomerInfo;
import com.rashed.pharmacy.dao.CustomerInfoDAO;
import com.rashed.pharmacy.model.Sales;
import com.rashed.pharmacy.dao.SalesDAO;
import com.rashed.pharmacy.model.Transaction;
import com.rashed.pharmacy.dao.TransactionDAO;
import com.rashed.pharmacy.util.*;

public class PurchaseController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/order/purchaseAdd.jsp";
	private static String LIST_PURCHASE = "/jsp/order/purchaseList.jsp";
	private static String ENQUIRY = "/jsp/order/purchaseEnquiry.jsp";
	
	private PurchaseDAO phdao;
	private ProductDAO pdao;
	private CustomerInfoDAO cdao;
	private SalesDAO sdao;
	private AccountDAO adao;
	private DayWiseAccountBalanceDAO dwabdao;
	private TransactionDAO tdao;
	
	String action = "";
	String message = "";	
       
    public PurchaseController() {
        super();
        phdao = new PurchaseDAO();
        pdao = new ProductDAO();
        cdao = new CustomerInfoDAO();
        sdao = new SalesDAO();
        adao = new AccountDAO();
        dwabdao = new DayWiseAccountBalanceDAO();
        tdao = new TransactionDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			String purchase_id = request.getParameter("purchase_id");
			phdao.delete(purchase_id);
			forward=LIST_PURCHASE;
			request.setAttribute("purchases", phdao.getAllPurchase());
			message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("cancel")){
			String purchase_id = request.getParameter("purchase_id");
			String strOrderStatus = phdao.getSelectedOtherID(purchase_id).getOrder_status();
			String strDeliveryStatus = phdao.getSelectedOtherID(purchase_id).getDelivery_status();
			/*if (!strOrderStatus.equals("A")) {
				phdao.cancel(purchase_id);
				message = "Order " + purchase_id + " Cancelled Successfully!!!";
				request.setAttribute("success", message);
			} else {
				message = "Approved Order can not be cancel !!!";
				request.setAttribute("success", message);
			}*/
			
			if (!strDeliveryStatus.equals("D") && !strDeliveryStatus.equals("C") && !strDeliveryStatus.equals("R")) {
				phdao.cancel(purchase_id);
				
				tdao.purchaseToTransaction(purchase_id, action);
				
				phdao.delete(purchase_id);
				
				message = "Order " + purchase_id + " Cancelled Successfully!!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Order Already Cancelled !!!";
					request.setAttribute("success", message);
				} else if (strDeliveryStatus.equals("C")) {
					message = "Order Already Cancelled !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A") && strDeliveryStatus.equals("D")) {
					message = "Received Order can not be cancel!!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A") && strDeliveryStatus.equals("R")) {
					message = "Already Return !!!";
					request.setAttribute("success", message);
				}
			}
			
			forward=LIST_PURCHASE;
			request.setAttribute("purchases", phdao.getAllPurchase());
		} else if(action.equalsIgnoreCase("approve")){
			String purchase_id = request.getParameter("purchase_id");
			String strOrderStatus = phdao.getSelectedOtherID(purchase_id).getOrder_status();
			String strProduct = phdao.getSelectedOtherID(purchase_id).getProduct_id();
			int intOrderQuantity = phdao.getSelectedOtherID(purchase_id).getOrder_quantity();
			if (!strOrderStatus.equals("A") && !strOrderStatus.equals("C")) {
				phdao.approve(purchase_id);
				
				message = "Order " + purchase_id + " Approved Successfully!!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Cancelled Order can not be Approved !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A")) {
					message = "Already Approved !!!";
					request.setAttribute("success", message);
				}
			}
			forward=LIST_PURCHASE;
			request.setAttribute("purchases", phdao.getAllPurchase());
		} else if(action.equalsIgnoreCase("receiveApprove")){
			String purchase_id = request.getParameter("purchase_id");
			String strOrderStatus = phdao.getSelectedOtherID(purchase_id).getOrder_status();
			String strDeliveryStatus = phdao.getSelectedOtherID(purchase_id).getDelivery_status();
			String strRequisition = phdao.getSelectedOtherID(purchase_id).getRequisition_id();
			String strProduct = phdao.getSelectedOtherID(purchase_id).getProduct_id();
			int intOrderQuantity = phdao.getSelectedOtherID(purchase_id).getOrder_quantity();
			String strFromAccount = phdao.getSelectedOtherID(purchase_id).getFrom_account_id();
			String strToAccount = phdao.getSelectedOtherID(purchase_id).getTo_account_id();
			double doubleTotalAmount = phdao.getSelectedOtherID(purchase_id).getTotal_amount();

			if (strOrderStatus.equals("A") && !strDeliveryStatus.equals("D") && !strDeliveryStatus.equals("C")) {
				phdao.receiveApprove(purchase_id);
				
				pdao.purchaseStockUpdate(strProduct, intOrderQuantity);
				
				SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
				Date date = new Date();  
				String strCurrentDateTime = formatter.format(date);
				
				adao.purchaseBalanceUpdate(strFromAccount, doubleTotalAmount, strCurrentDateTime);
				
				dwabdao.purchaseDayBalance(strFromAccount, doubleTotalAmount, strCurrentDateTime);
				
				message = "Purchase " + purchase_id + " Received Successfully!!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Cancelled Order can not be Received !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("P")) {
					message = "Pending Order can not be Received !!!";
					request.setAttribute("success", message);
				} else if (strDeliveryStatus.equals("C")) {
					message = "Cancelled Order can not be Received !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A") && strDeliveryStatus.equals("D")) {
					message = "Already Received !!!";
					request.setAttribute("success", message);
				}
			}
			forward=LIST_PURCHASE;
			request.setAttribute("purchases", phdao.getAllPurchase());
		} else if(action.equalsIgnoreCase("purchaseReturn")){
			String purchase_id = request.getParameter("purchase_id");
			String strOrderStatus = phdao.getSelectedOtherID(purchase_id).getOrder_status();
			String strDeliveryStatus = phdao.getSelectedOtherID(purchase_id).getDelivery_status();
			String strRequisition = phdao.getSelectedOtherID(purchase_id).getRequisition_id();
			String strProduct = phdao.getSelectedOtherID(purchase_id).getProduct_id();
			int intOrderQuantity = phdao.getSelectedOtherID(purchase_id).getOrder_quantity();
			if (strOrderStatus.equals("A") && !strDeliveryStatus.equals("D") && !strDeliveryStatus.equals("C") && !strDeliveryStatus.equals("R")) {
				phdao.deliveryReturn(purchase_id);
				
				tdao.purchaseToTransaction(purchase_id, action);
				
				phdao.delete(purchase_id);
				
				message = "Purchase " + purchase_id + " Delivery Return !!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Order Already Cancelled !!!";
					request.setAttribute("success", message);
				} else if (strDeliveryStatus.equals("C")) {
					message = "Order Already Cancelled !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A") && strDeliveryStatus.equals("D")) {
					message = "Already Received !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A") && strDeliveryStatus.equals("R")) {
					message = "Already Return !!!";
					request.setAttribute("success", message);
				}
			}
			forward=LIST_PURCHASE;
			request.setAttribute("purchases", phdao.getAllPurchase());
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String purchase_id = request.getParameter("purchase_id");
			Purchase p = phdao.getPurchaseById(purchase_id);
			request.setAttribute("purchase", p);
			// for get all the Product_id when update requisition [S]
			request.setAttribute("allProduct", pdao.getAllProduct());
			// for get all the Product_id when update requisition [E]
			
			// selected other respective id during update [S]
			request.setAttribute("selectedProductId", phdao.getSelectedOtherID(purchase_id).getProduct_id());
			request.setAttribute("selectedBonusId", phdao.getSelectedOtherID(purchase_id).getBonus_id());
			// selected other respective id during update [E]
		} else if(action.equalsIgnoreCase("purchaseList")){
			forward = LIST_PURCHASE;
			request.setAttribute("purchases", phdao.getAllPurchase());
		} else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String purchase_id = request.getParameter("purchase_id");
			Purchase p = phdao.getPurchaseById(purchase_id);
			request.setAttribute("purchase", p);
		} else {
			forward = INSERT_OR_EDIT;
			// generated auto increment id during add [S]
			request.setAttribute("purchaseId", phdao.getPurchaseID().getPurchase_id());
			// generated auto increment id during add [E]
			
			// for get all the Product_id when add requisition [S]
			request.setAttribute("allProduct", pdao.getAllProduct());
			// for get all the Product_id when add requisition [E]
			
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		Purchase p = new Purchase();
		
		p.setPurchase_id(request.getParameter("purchase_id"));
		p.setPurchase_type(request.getParameter("purchase_type"));
		p.setRequisition_id(request.getParameter("requisition_id"));
		p.setProduct_id(request.getParameter("product_id"));
		p.setProduct_name(request.getParameter("product_name"));
		p.setPack_type(request.getParameter("pack_type"));
		p.setPack_size(request.getParameter("pack_size"));
		p.setPiceces(Integer.parseInt(request.getParameter("piceces")));
		p.setBonus_id(request.getParameter("bonus_id"));
		p.setBonus_name(request.getParameter("bonus_name"));
		p.setOrder_pack(request.getParameter("order_pack"));
		p.setOrder_quantity(Integer.parseInt(request.getParameter("order_quantity")));
		p.setRate_per_piceces(Double.parseDouble(request.getParameter("rate_per_piceces")));
		p.setRate_per_box(Double.parseDouble(request.getParameter("rate_per_box")));
		p.setTp_price(Double.parseDouble(request.getParameter("tp_price")));
		p.setTotal_tp_price(Double.parseDouble(request.getParameter("total_tp_price")));
		p.setDiscount_amt(Double.parseDouble(request.getParameter("discount_amt")));
		p.setTotal_amount(Double.parseDouble(request.getParameter("total_amount")));
		p.setNeeded_date_time(request.getParameter("needed_date_time"));
		p.setFrom_account_id(request.getParameter("from_account_id"));
		p.setTo_account_id(request.getParameter("to_account_id"));
		p.setOrder_status(request.getParameter("order_status"));
		p.setDelivery_status(request.getParameter("delivery_status"));
		p.setCreated(request.getParameter("created"));
		p.setUpdated(request.getParameter("updated"));
		p.setCreated_by(request.getParameter("created_by"));
		p.setUpdated_by(request.getParameter("updated_by"));
	
		String purchase_id = request.getParameter("purchase_id");

		if(action.equalsIgnoreCase("save")){
			phdao.save(p);
		} else if(action.equalsIgnoreCase("edit")){
			p.setPurchase_id(purchase_id);
			phdao.update(p);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_PURCHASE);
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		request.setAttribute("purchases", phdao.getAllPurchase());
		
		rd.forward(request, response);
	}

}
