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
import com.rashed.pharmacy.model.RequisitionProduct;
import com.rashed.pharmacy.dao.RequisitionProductDAO;
import com.rashed.pharmacy.model.SalesMain;
import com.rashed.pharmacy.dao.AccountDAO;
import com.rashed.pharmacy.dao.DayWiseAccountBalanceDAO;
import com.rashed.pharmacy.dao.ProfitLossDAO;
import com.rashed.pharmacy.dao.SalesMainDAO;
import com.rashed.pharmacy.dao.SalesProductDAO;
import com.rashed.pharmacy.dao.CustomerPurchaseMainDAO;
import com.rashed.pharmacy.dao.CustomerTransactionMainDAO;
import com.rashed.pharmacy.util.*;

public class SalesMainController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/order/salesMainAdd.jsp";
	private static String LIST_SALESMAIN = "/jsp/order/salesMainList.jsp";
	private static String ENQUIRY = "/jsp/order/salesMainEnquiry.jsp";
	private static String LIST_SALESPRODUCT = "/jsp/order/salesProductList.jsp";
	private static String LIST_SALESPRODUCTENQUIRY = "/jsp/order/salesProductListEnquiry.jsp";
	
	private RequisitionMultiDAO rmdao;
	private RequisitionProductDAO rpdao;
	private ProductDAO pdao;
	private CustomerInfoDAO cdao;
	//private SalesDAO sdao;
	private SalesmanInfoDAO smdao;
	//private RequisitionProductDAO rpdao;
	private SalesMainDAO smmdao;
	private SalesProductDAO spdao;
	private CustomerPurchaseMainDAO cpmdao;
	private CustomerTransactionMainDAO ctmdao;
	private AccountDAO adao;
	private DayWiseAccountBalanceDAO dwabdao;
	private ProfitLossDAO pldao;
	
	String action = "";
	String message = "";
	
       
    public SalesMainController() {
        super();
        rmdao = new RequisitionMultiDAO();
        rpdao = new RequisitionProductDAO();
        pdao = new ProductDAO();
        cdao = new CustomerInfoDAO();
        //sdao = new SalesDAO();
        smdao = new SalesmanInfoDAO();
        //rpdao = new RequisitionProductDAO();
        smmdao = new SalesMainDAO();
        spdao = new SalesProductDAO();
        cpmdao = new CustomerPurchaseMainDAO();
        ctmdao = new CustomerTransactionMainDAO();
        adao = new AccountDAO();
        dwabdao = new DayWiseAccountBalanceDAO();
        pldao = new ProfitLossDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			String sales_id = request.getParameter("sales_id");
			//smmdao.delete(requisition_id);
			String strOrderStatus = smmdao.getSelectedOtherID(sales_id).getOrder_status();
			String date_time = smmdao.getSelectedOtherID(sales_id).getDate_time();
			
			if (!strOrderStatus.equals("A") && !strOrderStatus.equals("S")) {
				smmdao.delete(sales_id);
				message = "Order " + sales_id + " deleted Successfully!!!";
				request.setAttribute("success", message);
			} else {
					message = "Approved Order can not be deleted !!!";
					request.setAttribute("success", message);
			}
			forward=LIST_SALESMAIN;
			request.setAttribute("salesMains", smmdao.getAllSalesMain());
			/*message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);*/
		} else if(action.equalsIgnoreCase("cancel")){
			String sales_id = request.getParameter("sales_id");
			String strOrderStatus = smmdao.getSelectedOtherID(sales_id).getOrder_status();
			/*String strProduct = sdao.getSelectedOtherID(sales_id).getProduct_id();
			String strRequisition = sdao.getSelectedOtherID(sales_id).getRequisition_id();
			int intOrderQuantity = sdao.getSelectedOtherID(sales_id).getOrder_quantity();*/
			
			if (!strOrderStatus.equals("S")) {
				smmdao.cancel(sales_id);
				
				/*pdao.returnStockUpdate(strProduct, intOrderQuantity);
				
				ctdao.salesToCustomerTransaction(sales_id, action);
				
				rdao.delete(strRequisition);
				
				sdao.delete(sales_id);*/
				
				message = "Sales " + sales_id + " Cancelled Successfully!!!";
				request.setAttribute("success", message);
			} else {
				message = "Success Sales can not be cancelled !!!";
				request.setAttribute("success", message);
			}
			
			forward=LIST_SALESMAIN;
			request.setAttribute("salesMains", smmdao.getAllSalesMain());
		} else if(action.equalsIgnoreCase("approve")){
			String sales_id = request.getParameter("sales_id");
			String requisition_id = smmdao.getSelectedOtherID(sales_id).getRequisition_id();
			String date_time = smmdao.getSelectedOtherID(sales_id).getDate_time();
			String strOrderStatus = smmdao.getSelectedOtherID(sales_id).getOrder_status();
			
			if (!strOrderStatus.equals("S") && !strOrderStatus.equals("C")) {
				smmdao.approve(sales_id);
				// set sales_product order_status='S' based on sales_main id [S]
				spdao.approveByMainSales(requisition_id, date_time);
				// set sales_product order_status='S' based on sales_main id [E]
				
				// requisition_multi to sales_main [S]
				//smmdao.requisitionMultiToSalesMain(requisition_id, date_time);
				// requisition_multi to sales_main [E]

				// for insert into sales_product one by one from a list based on requisition_product id and date time [S]
				//rpdao.getRequisitionProductToSalesProduct(requisition_id, date_time);
				//spdao.requisitionProductToSalesProduct(requisition_id, date_time);
				// for insert into sales_product one by one from a list based on requisition_product id and date time [E]
				/*sdao.requisitionToSales(requisition_id);
				
				pdao.stockUpdate(strProduct, intOrderQuantity);*/
				// for update stock one by one from a list based on requisition_multi id and date_time [S]
				/*rpdao.getProdcutIdForStockUpdate(requisition_id, date_time);*/
				// for update stock one by one from a list based on requisition_multi id and date_time [E]
				
				message = "Sales " + sales_id + " Approved Successfully!!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Cancelled Sales can not be Approved !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("S")) {
					message = "Already Success !!!";
					request.setAttribute("success", message);
				}
			}
			
			forward=LIST_SALESMAIN;
			request.setAttribute("salesMains", smmdao.getAllSalesMain());
		} else if(action.equalsIgnoreCase("deliveryApprove")){
			String sales_id = request.getParameter("sales_id");
			String strSalesType = smmdao.getSelectedOtherID(sales_id).getSales_type();
			String strOrderStatus = smmdao.getSelectedOtherID(sales_id).getOrder_status();
			String strDeliveryStatus = smmdao.getSelectedOtherID(sales_id).getDelivery_status();
			String strRequisition = smmdao.getSelectedOtherID(sales_id).getRequisition_id();
			String date_time = smmdao.getSelectedOtherID(sales_id).getDate_time();
			/*String strProduct = sdao.getSelectedOtherID(sales_id).getProduct_id();
			int intOrderQuantity = sdao.getSelectedOtherID(sales_id).getOrder_quantity();*/
			String strFromAccount = smmdao.getSelectedOtherID(sales_id).getFrom_account_id();
			String strToAccount = smmdao.getSelectedOtherID(sales_id).getTo_account_id();
			double doubleTotalAmount = smmdao.getSelectedOtherID(sales_id).getTotal_amount();

			if (strOrderStatus.equals("S") && !strDeliveryStatus.equals("D") && !strDeliveryStatus.equals("C")) {
				smmdao.deliveryApprove(sales_id);
				
				spdao.deliveryApproveByMainSales(sales_id, strRequisition, date_time);
				
				cpmdao.salesMainToCustomerPurchaseMain(strRequisition, date_time);
				
				spdao.getSalesProductToCustomerPurchaseProduct(strRequisition, date_time);
				
				// for insert data into account table [S]
				adao.balanceUpdate(strFromAccount, doubleTotalAmount);
				// for insert data into account table [E]
				
				// for insert data into day_wise_account_balance table [S]
				SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
				Date date = new Date();  
				String strCurrentDateTime = formatter.format(date);
				dwabdao.dayBalance(strFromAccount, doubleTotalAmount, strCurrentDateTime);
				// for insert data into day_wise_account_balance table [E]
				
				// for insert data into profit_loss table [S]
				spdao.getProdcutIdForProfitLoss(sales_id, strRequisition, date_time, strFromAccount, doubleTotalAmount, strCurrentDateTime);
				// for insert data into profit_loss table [E]
				
				// Sales Type not equals Manual then record deleted from Requisition table, because Manual sales don't have any requisition [S]
				if(!strSalesType.equals("Manual")){
					rpdao.deleteByIdDateTime(strRequisition, date_time);
					rmdao.deleteByIdDateTime(strRequisition, date_time);
				}
				// Sales Type not equals Manual then record deleted from Requisition table, because Manual sales don't have any requisition [E]
				
				/*cpdao.salesToCustomerPurchase(sales_id);
				
				//ctdao.salesToCustomerTransaction(sales_id, action);
				
				adao.balanceUpdate(strFromAccount, doubleTotalAmount);
				// for insert data into day_wise_account_balance table [S]
				SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
				Date date = new Date();  
				String strCurrentDateTime = formatter.format(date);
				dwabdao.dayBalance(strFromAccount, doubleTotalAmount, strCurrentDateTime);
				// for insert data into day_wise_account_balance table [E]
				
				// for insert data into profit_loss table [S]
				pldao.profitLossAmount(sales_id, strFromAccount, doubleTotalAmount, strProduct, intOrderQuantity, strCurrentDateTime);
				// for insert data into profit_loss table [E]
				
				rdao.delete(strRequisition);
				
				//pdao.stockUpdate(strProduct, intOrderQuantity);
*/				
				message = "Sales " + sales_id + " Delivered Successfully!!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Cancelled Sales can not be Delivered !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A")) {
					message = "Without Success Sales can not be Delivered !!!";
					request.setAttribute("success", message);
				} else if (strDeliveryStatus.equals("C")) {
					message = "Cancelled Delivered can not be Delivered !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("S") && strDeliveryStatus.equals("D")) {
					message = "Already Delivered !!!";
					request.setAttribute("success", message);
				}
			}
			forward=LIST_SALESMAIN;
			request.setAttribute("salesMains", smmdao.getAllSalesMain());
		} else if(action.equalsIgnoreCase("deliveryReturn")){
			String sales_id = request.getParameter("sales_id");
			String strSalesType = smmdao.getSelectedOtherID(sales_id).getSales_type();
			String strOrderStatus = smmdao.getSelectedOtherID(sales_id).getOrder_status();
			String strDeliveryStatus = smmdao.getSelectedOtherID(sales_id).getDelivery_status();
			String strRequisition = smmdao.getSelectedOtherID(sales_id).getRequisition_id();
			String date_time = smmdao.getSelectedOtherID(sales_id).getDate_time();
			String strFromAccount = smmdao.getSelectedOtherID(sales_id).getFrom_account_id();
			String strToAccount = smmdao.getSelectedOtherID(sales_id).getTo_account_id();
			double doubleTotalAmount = smmdao.getSelectedOtherID(sales_id).getTotal_amount();
			
			if (strOrderStatus.equals("S") && !strDeliveryStatus.equals("D") && !strDeliveryStatus.equals("C") && !strDeliveryStatus.equals("R")) {
				smmdao.deliveryReturn(sales_id);
				
				spdao.deliveryReturnByMainSales(sales_id, strRequisition, date_time);
				
				ctmdao.salesMainToCustomerTransactionMain(strRequisition, date_time);
				
				spdao.getSalesProductToCustomerTransactionProduct(strRequisition, date_time);
				
				spdao.getProdcutIdForStockUpdate(strRequisition, date_time);
				
				// Sales Type not equals Manual then record deleted from Requisition table, because Manual sales don't have any requisition [S]
				if(!strSalesType.equals("Manual")){
					rpdao.deleteByIdDateTime(strRequisition, date_time);
					rmdao.deleteByIdDateTime(strRequisition, date_time);
				}
				// Sales Type not equals Manual then record deleted from Requisition table, because Manual sales don't have any requisition [E]
				
				spdao.deleteByIdDateTime(strRequisition, date_time);
				smmdao.deleteByIdDateTime(strRequisition, date_time);
				
				/*pdao.returnStockUpdate(strProduct, intOrderQuantity);
				
				//ctdao.salesToCustomerTransaction(sales_id);
				ctdao.salesToCustomerTransaction(sales_id, action);
				
				rdao.delete(strRequisition);
				
				sdao.delete(sales_id);*/
				
				message = "Sales " + sales_id + " Delivery Return !!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Sales Already Cancelled !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A")) {
					message = "Without Success Sales can not be Delivered !!!";
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
			forward=LIST_SALESMAIN;
			request.setAttribute("salesMains", smmdao.getAllSalesMain());
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String sales_id = request.getParameter("sales_id");
			SalesMain sm = smmdao.getSalesMainById(sales_id);
			request.setAttribute("salesMain", sm);
			// for get all the Product_id when update requisition [S]
			/*request.setAttribute("allProduct", pdao.getAllProduct());*/
			// for get all the Product_id when update requisition [E]
			// for get all the Customer when update requisition [S]
			request.setAttribute("allCustomer", cdao.getAllCustomerInfo());
			// for get all the Customer when update requisition [E]
			// for get all the Salesman when update requisition [S]
			request.setAttribute("allSalesman", smdao.getAllSalesmanInfo());
			// for get all the Salesman when update requisition [E]
			
			// selected other respective id during update [S]
			request.setAttribute("selectedCustomerId", smmdao.getSelectedOtherID(sales_id).getCustomer_id());
			request.setAttribute("selectedSalesmanId", smmdao.getSelectedOtherID(sales_id).getSalesman_id());
			// selected other respective id during update [E]
		} else if(action.equalsIgnoreCase("salesMainList")){
			forward = LIST_SALESMAIN;
			request.setAttribute("salesMains", smmdao.getAllSalesMain());
		} else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String sales_id = request.getParameter("sales_id");
			SalesMain sm = smmdao.getSalesMainById(sales_id);
			request.setAttribute("salesMain", sm);
		} else if(action.equalsIgnoreCase("return")){
			forward = LIST_SALESPRODUCT;
			
			String sales_id = request.getParameter("sales_id");
			String requisition_id = request.getParameter("requisition_id");
			String date_time = request.getParameter("date_time");
			request.setAttribute("salesProducts", spdao.getAllSalesProductByMainIdDateTime(sales_id, requisition_id, date_time));
			// for transfer data into another page (Product Requisition) [S]
			request.setAttribute("sales_id", sales_id);
			request.setAttribute("requisition_id", requisition_id);
			request.setAttribute("strDateTime", date_time);
			request.setAttribute("customer_name", request.getParameter("customer_name"));
			request.setAttribute("mobile", request.getParameter("mobile"));
			// for transfer data into another page (Product Requisition) [E]
			// for Requisition Product sum total amount [S]
			request.setAttribute("sumTotalAmount", spdao.sumTotalAmount(sales_id, requisition_id, date_time).getTotal_amount());
			// for Requisition Product sum total amount [E]
		} else if(action.equalsIgnoreCase("salesProductListEnquiry")){
			forward = LIST_SALESPRODUCTENQUIRY;
			
			String sales_id = request.getParameter("sales_id");
			String requisition_id = request.getParameter("requisition_id");
			String date_time = request.getParameter("date_time");
			request.setAttribute("salesProducts", spdao.getAllSalesProductByMainIdDateTime(sales_id, requisition_id, date_time));
			// for transfer data into another page (Product Requisition) [S]
			request.setAttribute("sales_id", sales_id);
			request.setAttribute("requisition_id", requisition_id);
			request.setAttribute("date_time", date_time);
			request.setAttribute("customer_name", request.getParameter("customer_name"));
			request.setAttribute("mobile", request.getParameter("mobile"));
			// for transfer data into another page (Product Requisition) [E]
			// for Requisition Product sum total amount [S]
			request.setAttribute("sumTotalAmount", spdao.sumTotalAmount(sales_id, requisition_id, date_time).getTotal_amount());
			// for Requisition Product sum total amount [E]
		} else {
			forward = INSERT_OR_EDIT;
			// generated auto increment id during add [S]
			request.setAttribute("salesId", smmdao.getSalesMainID().getSales_id());
			// generated auto increment id during add [E]
			// for manual sales requisition id [S]
			request.setAttribute("requisition_id", rmdao.getRequisitionMultiID().getRequisition_id());
			//for manual sales requisition id [E]
			
			// for get all the Customer when add sales [S]
			request.setAttribute("allCustomer", cdao.getAllCustomerInfo());
			// for get all the Customer when add requisition [E]
			// for get all the Salesman when ad sales [S]
			request.setAttribute("allSalesman", smdao.getAllSalesmanInfo());
			// for get all the Salesman when add sales [E]
			// for get main account id when add sales [S]
			request.setAttribute("mainAccountId", adao.getMainAccount().getAccount_id());
			// for get main account id when add sales [E]
			
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		SalesMain sm = new SalesMain();
		
		sm.setSales_id(request.getParameter("sales_id"));
		sm.setSales_type(request.getParameter("sales_type"));
		sm.setRequisition_id(request.getParameter("requisition_id"));
		sm.setDate_time(request.getParameter("date_time"));
		sm.setCustomer_id(request.getParameter("customer_id"));
		sm.setCustomer_name(request.getParameter("customer_name"));
		sm.setMobile(request.getParameter("mobile"));
		sm.setNeeded_date_time(request.getParameter("needed_date_time"));
		sm.setFrom_account_id(request.getParameter("from_account_id"));
		sm.setTo_account_id(request.getParameter("to_account_id"));
		sm.setSalesman_id(request.getParameter("salesman_id"));
		sm.setTotal_amount(Double.parseDouble(request.getParameter("total_amount")));
		sm.setOrder_status(request.getParameter("order_status"));
		sm.setDelivery_status(request.getParameter("delivery_status"));
		sm.setCreated(request.getParameter("created"));
		sm.setUpdated(request.getParameter("updated"));
		sm.setCreated_by(request.getParameter("created_by"));
		sm.setUpdated_by(request.getParameter("updated_by"));
	
		String sales_id = request.getParameter("sales_id");
		String sales_type = request.getParameter("sales_type");
		String requisition_id = request.getParameter("requisition_id");
		String strDateTime = request.getParameter("date_time");

		if(action.equalsIgnoreCase("save")){
			smmdao.save(sm);
		} else if(action.equalsIgnoreCase("edit")){
			sm.setSales_id(sales_id);
			smmdao.update(sm);
		}
		
		/*RequestDispatcher rd = request.getRequestDispatcher(LIST_REQUISITIONMULTI);*/
		RequestDispatcher rd = request.getRequestDispatcher(LIST_SALESPRODUCT);
		//request.setAttribute("salesProducts", spdao.getAllSalesProductByMainIdDateTime(requisition_id, strDateTime));
		request.setAttribute("salesProducts", spdao.getAllSalesProductByMainIdDateTime(sales_id, requisition_id, strDateTime));

		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		/*request.setAttribute("requisitionMultis", rmdao.getAllRequisitionMulti());*/
		// for transfer data into another page (Product Requisition) [S]
		request.setAttribute("sales_id", sales_id);
		request.setAttribute("sales_type", sales_type);
		request.setAttribute("requisition_id", requisition_id);
		request.setAttribute("strDateTime", strDateTime);
		request.setAttribute("customer_name", request.getParameter("customer_name"));
		request.setAttribute("mobile", request.getParameter("mobile"));
		// for transfer data into another page (Product Requisition) [E]
		// for Requisition Product sum total amount [S]
		request.setAttribute("sumTotalAmount", spdao.sumTotalAmount(sales_id, requisition_id, strDateTime).getTotal_amount());
		// for Requisition Product sum total amount [E]
		
		rd.forward(request, response);
	}

}
