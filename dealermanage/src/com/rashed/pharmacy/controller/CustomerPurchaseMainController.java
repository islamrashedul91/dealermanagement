package com.rashed.pharmacy.controller;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import com.google.zxing.WriterException;

import com.rashed.pharmacy.dao.RequisitionMultiDAO;
import com.rashed.pharmacy.dao.ProductDAO;
import com.rashed.pharmacy.dao.CustomerInfoDAO;
import com.rashed.pharmacy.dao.SalesDAO;
import com.rashed.pharmacy.dao.SalesmanInfoDAO;
import com.rashed.pharmacy.dao.RequisitionProductDAO;
import com.rashed.pharmacy.model.SalesMain;
import com.rashed.pharmacy.dao.SalesMainDAO;
import com.rashed.pharmacy.dao.SalesProductDAO;
import com.rashed.pharmacy.model.CustomerPurchaseMain;
import com.rashed.pharmacy.dao.CustomerPurchaseMainDAO;
import com.rashed.pharmacy.dao.CustomerPurchaseProductDAO;
import com.rashed.pharmacy.util.*;

public class CustomerPurchaseMainController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	/*private static String INSERT_OR_EDIT = "/jsp/order/salesMainAdd.jsp";*/
	private static String LIST_CUSTOMERPURCHASEMAIN = "/jsp/order/customerPurchaseMainList.jsp";
	private static String ENQUIRY = "/jsp/order/customerPurchaseMainEnquiry.jsp";
	private static String LIST_CUSTOMERPURCHASEPRODUCT = "/jsp/order/customerPurchaseProductList.jsp";
	private static String LIST_CUSTOMERPURCHASEPRODUCTENQUIRY = "/jsp/order/customerPurchaseProductListEnquiry.jsp";
	
	//private RequisitionMultiDAO rmdao;
	//private ProductDAO pdao;
	//private CustomerInfoDAO cdao;
	//private SalesDAO sdao;
	//private SalesmanInfoDAO smdao;
	//private RequisitionProductDAO rpdao;
	//private SalesMainDAO smmdao;
	//private SalesProductDAO spdao;
	private CustomerPurchaseMainDAO cpmdao;
	private CustomerPurchaseProductDAO cppdao;
	
	String action = "";
	String message = "";
	
       
    public CustomerPurchaseMainController() {
        super();
        //rmdao = new RequisitionMultiDAO();
        //pdao = new ProductDAO();
        //cdao = new CustomerInfoDAO();
        //sdao = new SalesDAO();
        //smdao = new SalesmanInfoDAO();
        //rpdao = new RequisitionProductDAO();
        //smmdao = new SalesMainDAO();
        //spdao = new SalesProductDAO();
        cpmdao = new CustomerPurchaseMainDAO();
        cppdao = new CustomerPurchaseProductDAO();
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
			//smmdao.delete(requisition_id);
			String strOrderStatus = cpmdao.getSelectedOtherID(purchase_id).getOrder_status();
			String date_time = cpmdao.getSelectedOtherID(purchase_id).getDate_time();
			
			if (!strOrderStatus.equals("A") && !strOrderStatus.equals("S")) {
				cpmdao.delete(purchase_id);
				message = "Purchase " + purchase_id + " deleted Successfully!!!";
				request.setAttribute("success", message);
			} else {
					message = "Approved Purchase can not be deleted !!!";
					request.setAttribute("success", message);
			}
			forward=LIST_CUSTOMERPURCHASEMAIN;
			request.setAttribute("customerPurchaseMains", cpmdao.getAllCustomerPurchaseMain());
			/*message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);*/
		} else if(action.equalsIgnoreCase("cancel")){
			String purchase_id = request.getParameter("purchase_id");
			String strOrderStatus = cpmdao.getSelectedOtherID(purchase_id).getOrder_status();
			/*String strProduct = sdao.getSelectedOtherID(sales_id).getProduct_id();
			String strRequisition = sdao.getSelectedOtherID(sales_id).getRequisition_id();
			int intOrderQuantity = sdao.getSelectedOtherID(sales_id).getOrder_quantity();*/
			
			if (!strOrderStatus.equals("S")) {
				cpmdao.cancel(purchase_id);
				
				/*pdao.returnStockUpdate(strProduct, intOrderQuantity);
				
				ctdao.salesToCustomerTransaction(sales_id, action);
				
				rdao.delete(strRequisition);
				
				sdao.delete(sales_id);*/
				
				message = "Purchase " + purchase_id + " Cancelled Successfully!!!";
				request.setAttribute("success", message);
			} else {
				message = "Success Purchase can not be cancelled !!!";
				request.setAttribute("success", message);
			}
			
			forward=LIST_CUSTOMERPURCHASEMAIN;
			request.setAttribute("customerPurchaseMains", cpmdao.getAllCustomerPurchaseMain());
		} else if(action.equalsIgnoreCase("customerPurchaseMainList")){
			forward = LIST_CUSTOMERPURCHASEMAIN;
			request.setAttribute("customerPurchaseMains", cpmdao.getAllCustomerPurchaseMain());
		} else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String purchase_id = request.getParameter("purchase_id");
			CustomerPurchaseMain cpm = cpmdao.getCustomerPurchaseMainById(purchase_id);
			request.setAttribute("customerPurchaseMain", cpm);
		} else if(action.equalsIgnoreCase("return")){
			forward = LIST_CUSTOMERPURCHASEPRODUCT;
			
			String purchase_id = request.getParameter("purchase_id");
			String requisition_id = request.getParameter("requisition_id");
			String date_time = request.getParameter("date_time");
			request.setAttribute("customerPurchaseProducts", cppdao.getAllCustomerPurchaseProductByMainIdDateTime(purchase_id, requisition_id, date_time));
			// for transfer data into another page (Product Requisition) [S]
			request.setAttribute("purchase_id", purchase_id);
			request.setAttribute("requisition_id", requisition_id);
			request.setAttribute("strDateTime", date_time);
			request.setAttribute("customer_name", request.getParameter("customer_name"));
			request.setAttribute("mobile", request.getParameter("mobile"));
			// for transfer data into another page (Product Requisition) [E]
			// for Requisition Product sum total amount [S]
			//request.setAttribute("sumTotalAmount", spdao.sumTotalAmount(purchase_id, requisition_id, date_time).getTotal_amount());
			request.setAttribute("sumTotalAmount", cppdao.sumTotalAmount(purchase_id, requisition_id, date_time).getTotal_amount());
			// for Requisition Product sum total amount [E]
		} else if(action.equalsIgnoreCase("customerPurchaseProductListEnquiry")){
			forward = LIST_CUSTOMERPURCHASEPRODUCTENQUIRY;
			
			String purchase_id = request.getParameter("purchase_id");
			String requisition_id = request.getParameter("requisition_id");
			String date_time = request.getParameter("date_time");
			request.setAttribute("customerPurchaseProducts", cppdao.getAllCustomerPurchaseProductByMainIdDateTime(purchase_id, requisition_id, date_time));
			// for transfer data into another page (Product Requisition) [S]
			request.setAttribute("purchase_id", purchase_id);
			request.setAttribute("requisition_id", requisition_id);
			request.setAttribute("date_time", date_time);
			request.setAttribute("customer_name", request.getParameter("customer_name"));
			request.setAttribute("mobile", request.getParameter("mobile"));
			// for transfer data into another page (Product Requisition) [E]
			// for Requisition Product sum total amount [S]
			request.setAttribute("sumTotalAmount", cppdao.sumTotalAmount(purchase_id, requisition_id, date_time).getTotal_amount());
			// for Requisition Product sum total amount [E]
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

}
