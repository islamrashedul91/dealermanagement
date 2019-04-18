package com.rashed.pharmacy.controller;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.websocket.Session;

import com.google.zxing.WriterException;
import com.rashed.pharmacy.model.CustomerTransactionMain;
import com.rashed.pharmacy.model.SalesProduct;
import com.rashed.pharmacy.dao.CustomerTransactionMainDAO;
import com.rashed.pharmacy.dao.SalesProductDAO;
import com.rashed.pharmacy.model.RequisitionProduct;
import com.rashed.pharmacy.dao.RequisitionProductDAO;
import com.rashed.pharmacy.model.RequisitionMulti;
import com.rashed.pharmacy.dao.RequisitionMultiDAO;
import com.rashed.pharmacy.model.Product;
import com.rashed.pharmacy.dao.ProductDAO;
import com.rashed.pharmacy.model.CustomerInfo;
import com.rashed.pharmacy.dao.CustomerInfoDAO;
import com.rashed.pharmacy.model.Sales;
import com.rashed.pharmacy.dao.SalesDAO;
import com.rashed.pharmacy.model.SalesmanInfo;
import com.rashed.pharmacy.dao.SalesmanInfoDAO;
import com.rashed.pharmacy.model.SalesMain;
import com.rashed.pharmacy.dao.SalesMainDAO;

import com.rashed.pharmacy.model.PurchaseMain;
import com.rashed.pharmacy.dao.PurchaseMainDAO;
import com.rashed.pharmacy.model.PurchaseProduct;
import com.rashed.pharmacy.dao.PurchaseProductDAO;
import com.rashed.pharmacy.dao.TransactionMainDAO;
import com.rashed.pharmacy.util.*;

public class PurchaseProductController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/order/purchaseProductAdd.jsp";
	private static String LIST_PURCHASEPRODUCT = "/jsp/order/purchaseProductList.jsp";
	private static String ENQUIRY = "/jsp/order/purchaseProductEnquiry.jsp";
	
	private RequisitionProductDAO rpdao;
	private ProductDAO pdao;
	private CustomerInfoDAO cdao;
	private SalesDAO sdao;
	private SalesmanInfoDAO smdao;
	private RequisitionMultiDAO rmdao;
	private SalesProductDAO spdao;
	private SalesMainDAO smmdao;
	private CustomerTransactionMainDAO ctmdao;
	
	private PurchaseMainDAO pmdao;
	private PurchaseProductDAO ppdao;
	private TransactionMainDAO tmdao;
	
	String action = "";
	String message = "";
	
       
    public PurchaseProductController() {
        super();
        rpdao = new RequisitionProductDAO();
        pdao = new ProductDAO();
        cdao = new CustomerInfoDAO();
        sdao = new SalesDAO();
        smdao = new SalesmanInfoDAO();
        rmdao = new RequisitionMultiDAO();
        spdao = new SalesProductDAO();
        smmdao = new SalesMainDAO();
        ctmdao = new CustomerTransactionMainDAO();
        
        pmdao = new PurchaseMainDAO();
        ppdao = new PurchaseProductDAO();
        tmdao = new TransactionMainDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			String purchase_product_id = request.getParameter("purchase_product_id");
			//rpdao.delete(requisition_product_id);
			String strOrderStatus = ppdao.getSelectedOtherID(purchase_product_id).getOrder_status();
			if (!strOrderStatus.equals("A")) {
				ppdao.delete(purchase_product_id);
				message = "Purchase " + purchase_product_id + " deleted Successfully!!!";
				request.setAttribute("success", message);
			} else {
				message = "Approved Purchase can not be deleted !!!";
				request.setAttribute("success", message);
			}
			forward=LIST_PURCHASEPRODUCT;
			request.setAttribute("purchaseProducts", ppdao.getAllPurchaseProduct());
			/*message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);*/
		} else if(action.equalsIgnoreCase("cancel")){
			String purchase_product_id = request.getParameter("purchase_product_id");
			String strPurchaseId = ppdao.getSelectedOtherID(purchase_product_id).getPurchase_id();
			String strOrderStatus = ppdao.getSelectedOtherID(purchase_product_id).getOrder_status();
			String strProduct = ppdao.getSelectedOtherID(purchase_product_id).getProduct_id();
			int intOrderQuantity = ppdao.getSelectedOtherID(purchase_product_id).getOrder_quantity();
			
			if (!strOrderStatus.equals("S")) {
				ppdao.cancel(purchase_product_id);
				
				/*pdao.returnStockUpdate(strProduct, intOrderQuantity);
				
				ctdao.salesToCustomerTransaction(sales_product_id, action);
				
				rdao.delete(strRequisition);
				
				sdao.delete(sales_product_id);*/
				
				message = "Purchase " + purchase_product_id + " Cancelled Successfully!!!";
				request.setAttribute("success", message);
			} else {
				message = "Success Purchase can not be cancelled !!!";
				request.setAttribute("success", message);
			}
			
			forward=LIST_PURCHASEPRODUCT;
			request.setAttribute("purchaseProducts", ppdao.getAllPurchaseProduct());
		} else if(action.equalsIgnoreCase("approve")){
			String purchase_product_id = request.getParameter("purchase_product_id");
			String strPurchaseId = ppdao.getSelectedOtherID(purchase_product_id).getPurchase_id();
			String strOrderStatus = ppdao.getSelectedOtherID(purchase_product_id).getOrder_status();
			String strProduct = ppdao.getSelectedOtherID(purchase_product_id).getProduct_id();
			int intOrderQuantity = ppdao.getSelectedOtherID(purchase_product_id).getOrder_quantity();
			if (!strOrderStatus.equals("S") && !strOrderStatus.equals("C")) {
				ppdao.approve(purchase_product_id);
				
				//Sales s = new Sales();
				/*sdao.requisitionToSales(requisition_product_id);
				
				pdao.stockUpdate(strProduct, intOrderQuantity);*/
				
				message = "Purchase " + purchase_product_id + " Approved Successfully!!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Cancelled Purchase can not be Approved !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("S")) {
					message = "Already Success !!!";
					request.setAttribute("success", message);
				}
			}
			
			forward=LIST_PURCHASEPRODUCT;
			request.setAttribute("purchaseProducts", ppdao.getAllPurchaseProduct());
		} else if(action.equalsIgnoreCase("deliveryReturn")){
			String purchase_product_id = request.getParameter("purchase_product_id");
			String strPurchaseId = ppdao.getSelectedOtherID(purchase_product_id).getPurchase_id();
			String strPurchaseType = ppdao.getSelectedOtherID(purchase_product_id).getPurchase_type();
			String strProduct = ppdao.getSelectedOtherID(purchase_product_id).getProduct_id();
			int intOrderQuantity = ppdao.getSelectedOtherID(purchase_product_id).getOrder_quantity();
			String strOrderStatus = ppdao.getSelectedOtherID(purchase_product_id).getOrder_status();
			String strDeliveryStatus = ppdao.getSelectedOtherID(purchase_product_id).getDelivery_status();
			String date_time = ppdao.getSelectedOtherID(purchase_product_id).getDate_time();
			double doubleTotalAmount = ppdao.getSelectedOtherID(purchase_product_id).getTotal_amount();
			
			if (strOrderStatus.equals("S") && !strDeliveryStatus.equals("D") && !strDeliveryStatus.equals("C") && !strDeliveryStatus.equals("R")) {
				
				ppdao.deliveryReturnByPurchaseProduct(purchase_product_id, strPurchaseId, date_time);
				
				String strTransactionID = ctmdao.getCustomerTransactionMainByIdDateTime(strPurchaseId, date_time).getTransaction_id();
				if(strTransactionID == null || strTransactionID.equals("")){
					tmdao.productPurchaseMainToTransactionMain(strPurchaseId, date_time);
				} else if(strTransactionID != null && !strTransactionID.equals("")){
					tmdao.returnTotalAmount(strPurchaseId, date_time);
				}
				//ctmdao.productSalesMainToCustomerTransactionMain(strRequisition, date_time);
				
				//spdao.getSalesProductToCustomerTransactionProduct(strRequisition, date_time);
				/*ppdao.purchaseProductToTransactionProduct(purchase_product_id, strPurchaseId, date_time);*/
				
				//spdao.getProdcutIdForStockUpdate(strRequisition, date_time);
				/*pdao.returnStockUpdate(strProduct, intOrderQuantity);*/
				
				// Sales Type not equals Manual then record deleted from Requisition table, because Manual sales don't have any requisition [S]
				/*if(!strSalesType.equals("Manual")){
					rpdao.deleteByIdDateTime(strRequisition, date_time);
					rmdao.deleteByIdDateTime(strRequisition, date_time);
				}*/
				// Sales Type not equals Manual then record deleted from Requisition table, because Manual sales don't have any requisition [E]
				
				ppdao.deleteByPPIdPIdDateTime(purchase_product_id, strPurchaseId, date_time);
				
				message = "Purchase " + purchase_product_id + " Delivery Return !!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Purchase Already Cancelled !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A")) {
					message = "Without Success Purchase can not be Delivered !!!";
					request.setAttribute("success", message);
				} else if (strDeliveryStatus.equals("C")) {
					message = "Delivery Already Cancelled !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("S") && strDeliveryStatus.equals("D")) {
					message = "Already Delivered !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("S") && strDeliveryStatus.equals("R")) {
					message = "Already Return !!!";
					request.setAttribute("success", message);
				}
			}
			forward=LIST_PURCHASEPRODUCT;

			request.setAttribute("purchaseProducts", ppdao.getAllPurchaseProductByMainIdDateTime(strPurchaseId, date_time));
			
			request.setAttribute("purchase_id", strPurchaseId);
			request.setAttribute("purchase_type", strPurchaseType);
			request.setAttribute("strDateTime", date_time);
			request.setAttribute("owner_name", request.getParameter("owner_name"));
			request.setAttribute("mobile", request.getParameter("mobile"));
			
			request.setAttribute("sumTotalAmount", ppdao.sumTotalAmount(strPurchaseId, date_time).getTotal_amount());
			
			pmdao.sumTotalAmountPP(strPurchaseId, date_time);
			
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String purchase_product_id = request.getParameter("purchase_product_id");
			PurchaseProduct pp = ppdao.getPurchaseProductById(purchase_product_id);
			request.setAttribute("purchaseProduct", pp);
			// for get all the Product_id when update requisition [S]
			request.setAttribute("allProduct", pdao.getAllProduct());
			// for get all the Product_id when update requisition [E]
			// for get all the Customer when update requisition [S]
			/*request.setAttribute("allCustomer", cdao.getAllCustomerInfo());*/
			// for get all the Customer when update requisition [E]
			// for get all the Salesman when update requisition [S]
			/*request.setAttribute("allSalesman", smdao.getAllSalesmanInfo());*/
			// for get all the Salesman when update requisition [E]
			
			// selected other respective id during update [S]
			/*request.setAttribute("selectedCustomerId", rpdao.getSelectedOtherID(requisition_product_id).getCustomer_id());*/
			request.setAttribute("selectedProductId", ppdao.getSelectedOtherID(purchase_product_id).getProduct_id());
			request.setAttribute("selectedBonusId", ppdao.getSelectedOtherID(purchase_product_id).getBonus_id());
			/*request.setAttribute("selectedSalesmanId", rpdao.getSelectedOtherID(requisition_product_id).getSalesman_id());*/
			// selected other respective id during update [E]
			
			// get value from Multi Requisition [S]
			/*request.setAttribute("requisition_multi_id1", requisition_multi_id);
			request.setAttribute("strDateTimeMulti1", strDateTimeMulti);
			request.setAttribute("customerNameMulti1", customerNameMulti);
			request.setAttribute("customerMobileMulti1", customerMobileMulti);*/
			// get value from Multi Requisition [S]
		} else if(action.equalsIgnoreCase("purchaseProductList")){
			forward = LIST_PURCHASEPRODUCT;
			request.setAttribute("purchaseProducts", ppdao.getAllPurchaseProduct());
		} else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String purchase_product_id = request.getParameter("purchase_product_id");
			PurchaseProduct pp = ppdao.getPurchaseProductById(purchase_product_id);
			request.setAttribute("purchaseProduct", pp);
		} else if(action.equalsIgnoreCase("enquiryEnquiry")){
			forward = ENQUIRY;
			String purchase_product_id = request.getParameter("purchase_product_id");
			PurchaseProduct pp = ppdao.getPurchaseProductById(purchase_product_id);
			request.setAttribute("purchaseProduct", pp);
		} else {
			forward = INSERT_OR_EDIT;
			// get value from Multi Requisition [S]
			/*request.setAttribute("requisition_multi_id1", requisition_multi_id);
			request.setAttribute("strDateTimeMulti1", strDateTimeMulti);
			request.setAttribute("customerNameMulti1", customerNameMulti);
			request.setAttribute("customerMobileMulti1", customerMobileMulti);*/
			// get value from Multi Requisition [S]
			
			// generated auto increment id during add [S]
			request.setAttribute("purchaseProductId", ppdao.getPurchaseProductID().getPurchase_product_id());
			// generated auto increment id during add [E]
			
			// for get all the Product_id when add requisition [S]
			request.setAttribute("allProduct", pdao.getAllProduct());
			// for get all the Product_id when add requisition [E]
			// for get all the Customer when add requisition [S]
			/*request.setAttribute("allCustomer", cdao.getAllCustomerInfo());*/
			// for get all the Customer when add requisition [E]
			// for get all the Salesman when ad requisition [S]
			/*request.setAttribute("allSalesman", smdao.getAllSalesmanInfo());*/
			// for get all the Salesman when add requisition [E]
			
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		PurchaseProduct pp = new PurchaseProduct();
		
		pp.setPurchase_product_id(request.getParameter("purchase_product_id"));
		pp.setPurchase_id(request.getParameter("purchase_id"));
		pp.setPurchase_type(request.getParameter("purchase_type"));
		pp.setDate_time(request.getParameter("date_time"));
		pp.setProduct_id(request.getParameter("product_id"));
		pp.setProduct_name(request.getParameter("product_name"));
		pp.setPack_type(request.getParameter("pack_type"));
		pp.setPack_size(request.getParameter("pack_size"));
		pp.setPiceces(Integer.parseInt(request.getParameter("piceces")));
		pp.setBonus_id(request.getParameter("bonus_id"));
		pp.setBonus_name(request.getParameter("bonus_name"));
		pp.setRate_per_piceces(Double.parseDouble(request.getParameter("rate_per_piceces")));
		pp.setRate_per_box(Double.parseDouble(request.getParameter("rate_per_box")));
		pp.setOrder_pack(request.getParameter("order_pack"));
		pp.setOrder_quantity(Integer.parseInt(request.getParameter("order_quantity")));
		pp.setTp_price(Double.parseDouble(request.getParameter("tp_price")));
		pp.setTotal_tp_price(Double.parseDouble(request.getParameter("total_tp_price")));
		pp.setDiscount_amt(Double.parseDouble(request.getParameter("discount_amt")));
		pp.setTotal_amount(Double.parseDouble(request.getParameter("total_amount")));
		pp.setOrder_status(request.getParameter("order_status"));
		pp.setDelivery_status(request.getParameter("delivery_status"));
		pp.setCreated(request.getParameter("created"));
		pp.setUpdated(request.getParameter("updated"));
		pp.setCreated_by(request.getParameter("created_by"));
		pp.setUpdated_by(request.getParameter("updated_by"));
	
		String purchase_product_id = request.getParameter("purchase_product_id");
		String purchase_id = request.getParameter("purchase_id");
		String purchase_type = request.getParameter("purchase_type");
		String strDateTime = request.getParameter("date_time");

		if(action.equalsIgnoreCase("save")){
			ppdao.save(pp);
		} else if(action.equalsIgnoreCase("edit")){
			pp.setPurchase_product_id(purchase_product_id);
			ppdao.update(pp);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_PURCHASEPRODUCT);
		request.setAttribute("purchaseProducts", ppdao.getAllPurchaseProductByMainIdDateTime(purchase_id, strDateTime));
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		/*request.setAttribute("requisitionProducts", rpdao.getAllRequisitionProduct());*/
		// for transfer data into another page (Product Requisition) [S]
		HttpSession session1 = request.getSession();
		
		request.setAttribute("purchase_id", request.getParameter("purchase_id"));
		request.setAttribute("strDateTime", request.getParameter("date_time"));
		request.setAttribute("purchase_type", purchase_type);
		request.setAttribute("owner_name", pmdao.getPurchaseMainByIdDateTime(purchase_id, strDateTime).getOwner_name());
		request.setAttribute("mobile", pmdao.getPurchaseMainByIdDateTime(purchase_id, strDateTime).getMobile());
		// for transfer data into another page (Product Requisition) [E]
		// for Requisition Product sum total amount [S]
		request.setAttribute("sumTotalAmount", ppdao.sumTotalAmount(purchase_id, strDateTime).getTotal_amount());
		// for Requisition Product sum total amount [E]
		
		// for insert into requisition_multi total_amount from Requisition Product sum total amount [S]
		pmdao.sumTotalAmountPP(purchase_id, strDateTime);
		// for insert into requisition_multi total_amount from Requisition Product sum total amount [E]
		
		rd.forward(request, response);
	}

}
