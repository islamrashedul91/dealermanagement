<jsp:include page="../../base.jsp"></jsp:include>
<br>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<%@ page import="java.text.SimpleDateFormat" %>
<%@ page import="java.util.Date" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Online Pharmacy</title>
<link rel="stylesheet" 	href="${pageContext.request.contextPath}/css/table.css">

<script language="JavaScript">

/* function customerChng() {
	oSelectOne = frmSave.elements["brand_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalText = split_selected_option_text[1];
	
	document.getElementById('brand_name').value = finalText;

} */

function customerChng() {
	oSelectOne = frmSave.elements["customer_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalTextName = split_selected_option_text[1];
	var finalTextMobile = split_selected_option_text[2];
	
	document.getElementById('customer_name').value = finalTextName;
	document.getElementById('mobile').value = finalTextMobile;

}

function productChng() {
	oSelectOne = frmSave.elements["product_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalTextName = split_selected_option_text[1];
	var finalTextType = split_selected_option_text[2];
	var finalTextSize = split_selected_option_text[3];
	var finalTextPieces = split_selected_option_text[4];
	var finalTextMRP = split_selected_option_text[5];
	
	document.getElementById('product_name').value = finalTextName;
	document.getElementById('pack_type').value = finalTextType;
	document.getElementById('pack_size').value = finalTextSize;
	document.getElementById('piceces').value = finalTextPieces;
	document.getElementById('mrp_price').value = finalTextMRP;

}

function bonusChng() {
	oSelectOne = frmSave.elements["bonus_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalText = split_selected_option_text[1];
	
	document.getElementById('bonus_name').value = finalText;

}

function quantityToTotalMRP() {
	
	var quantity = document.getElementById('order_quantity').value;
	var mrp = document.getElementById('mrp_price').value;
	var quantityMultiplyMrp = quantity * mrp;
	
	document.getElementById('total_mrp_price').value = quantityMultiplyMrp;

}

function discountToTotalAmount() {
	
	var discount = document.getElementById('discount_amt').value;
	var totalMrp = document.getElementById('total_mrp_price').value;
	var totalMrpMinusDiscount = totalMrp - discount;
	
	document.getElementById('total_amount').value = totalMrpMinusDiscount;

}

</script>

</head>
<body>
<%
String action = (String) session.getAttribute("action");
System.out.println("++++++"+action);
%>
<div class="mcontent">
			<div class="titlenav">
				<ul>					
					<li class="title"><a href="">
					<%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Sales Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Sales Update</td>
					<%
					}
					%>
					</a></li>
					<li class="bread"><a href="">Dashboard > Order Management > Sales List > <%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Sales Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Sales Update</td>
					<%
					}
					%></a></li>
				</ul>
			</div>
			<br>
		<div class="card">
			<div class="form-style-2">
<%
//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
Date date = new Date();  
String strDate = formatter.format(date);
%>	
	<form action="SalesController" method="post" name="frmSave">
		<div class="form-style-2-heading">Provide your information</div>
			<div class="square-44">
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field1"><span>Sales ID <span class="required">*</span></span>
				<!-- generated auto increment id during add [S] -->
				<input type="text" class="input-field-60" readonly="readonly" name="sales_id" id="sales_id" value="${salesId}"  maxlength=25 size=40 required />
				<!-- generated auto increment id during add [E] --> 
			</label> 
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field1"><span>Sales ID <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="sales_id" id="sales_id" value="${sales.sales_id}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<label for="field2"><span>Sales Type <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="sales_type" id="sales_type" value="${sales.sales_type}" maxlength=25 size=40 required /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field3"><span>Requisition ID </span>
				<select name="requisition_id" id="requisition_id" class="select-field-60" >
					<option value="" >Select one</option>
					<c:forEach items="${allRequisition}" var="ar">
						<option value="${ar.requisition_id}">${ar.requisition_id}</option>
					</c:forEach>
				</select> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field3"><span>Requisition ID </span>
				<select name="requisition_id" id="requisition_id" class="select-field-60" >
					<c:forEach items="${allRequisition}" var="ar">
						<option value="${ar.requisition_id}" ${ar.requisition_id == selectedRequisitionId ? 'selected="selected"' : ''}>${ar.requisition_id}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field4"><span>Customer ID </span>
				<select name="customer_id" id="customer_id" class="select-field-60" onchange="customerChng();" >
					<option value="" >Select one</option>
					<c:forEach items="${allCustomer}" var="ac">
						<option value="${ac.customer_id}">${ac.customer_name}-${ac.customer_id}  -  ${ac.customer_name}  -  ${ac.mobile}</option>
					</c:forEach>
				</select> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field4"><span>Customer ID </span>
				<select name="customer_id" id="customer_id" class="select-field-60" onchange="customerChng();" >
					<c:forEach items="${allCustomer}" var="ac">
						<option value="${ac.customer_id}" ${ac.customer_id == selectedCustomerId ? 'selected="selected"' : ''}>${ac.customer_id}  -  ${ac.customer_name}  -  ${ac.mobile}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<label for="field5"><span>Customer Name <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="customer_name" id="customer_name" value="${sales.customer_name}" maxlength=40 size=40 required /> 
			</label>
			
			<label for="field6"><span>Mobile <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="mobile" id="mobile" value="${sales.mobile}" maxlength=40 size=40 required /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field7"><span>Product ID </span>
				<select name="product_id" id="product_id" class="select-field-60" onchange="productChng();" >
					<option value="" >Select one</option>
					<c:forEach items="${allProduct}" var="ap">
						<option value="${ap.product_id}">${ap.product_name}  -  ${ap.product_name}  -  ${ap.pack_type}  -  ${ap.pack_size}  -  ${ap.piceces}  -  ${ap.mrp_price}</option>
					</c:forEach>
				</select> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field7"><span>Product ID </span>
				<select name="product_id" id="product_id" class="select-field-60" onchange="productChng();" >
					<c:forEach items="${allProduct}" var="ap">
						<option value="${ap.product_id}" ${ap.product_id == selectedProductId ? 'selected="selected"' : ''}>${ap.product_name}  -  ${ap.product_name}  -  ${ap.pack_type}  -  ${ap.pack_size}  -  ${ap.piceces}  -  ${ap.mrp_price}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<label for="field8"><span>Product Name <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="product_name" id="product_name" value="${sales.product_name}"  maxlength=100 size=40 required /> 
			</label>
			
			<label for="field9"><span>Pack Type <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="pack_type" id="pack_type" value="${sales.pack_type}"  maxlength=40 size=40 required /> 
			</label>
			
			<label for="field10"><span>Pack Size <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="pack_size" id="pack_size" value="${sales.pack_size}"  maxlength=25 size=40 required /> 
			</label>
			
			<label for="field11"><span>Pieces <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="piceces" id="piceces" value="${sales.piceces}"  maxlength=10 size=40 required /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field12"><span>Bonus ID </span>
				<select name="bonus_id" id="bonus_id" class="select-field-60" onchange="bonusChng();" >
					<option value="" >Select one</option>
					<c:forEach items="${allBonus}" var="ab">
						<option value="${ab.bonus_id}">${ab.bonus_id}  -  ${ab.bonus_name}</option>
					</c:forEach>
				</select> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field12"><span>Bonus ID </span>
				<select name="bonus_id" id="bonus_id" class="select-field-60" onchange="bonusChng();" >
					<c:forEach items="${allBonus}" var="ab">
						<option value="${ab.bonus_id}" ${ab.bonus_id == selectedBonusId ? 'selected="selected"' : ''}>${ab.bonus_id}  -  ${ab.bonus_name}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<label for="field13"><span>Bonus Name </span>
				<input type="text" class="input-field-60" readonly="readonly" name="bonus_name" id="bonus_name" value="${sales.bonus_name}"  maxlength=40 size=40 /> 
			</label>
			
			<label for="field14"><span>Order Pack </span>
				<input type="text" class="input-field-60" name="order_pack" id="order_pack" value="${sales.order_pack}"  maxlength=40 size=40 /> 
			</label>
			
			</div>
			
			&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
			
			<div class="square-44">
			
			<label for="field15"><span>Order Quantity <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="order_quantity" id="order_quantity" value="${sales.order_quantity}" onchange="quantityToTotalMRP();" maxlength=10 size=40 required /> 
			</label>
			
			<label for="field16"><span>MRP <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="mrp_price" id="mrp_price" value="${sales.mrp_price}" maxlength=10 size=40 required /> 
			</label>
			
			<label for="field17"><span>Total MRP BDT.<span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="total_mrp_price" id="total_mrp_price" value="${sales.total_mrp_price}"  maxlength=10 size=40 required /> 
			</label>
			
			<label for="field18"><span>Discount Amount <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="discount_amt" id="discount_amt" value="${sales.discount_amt}" onchange="discountToTotalAmount();" maxlength=10 size=40 required /> 
			</label>
			
			<label for="field19"><span>Total Amount BDT. <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="total_amount" id="total_amount" value="${sales.total_amount}"  maxlength=10 size=40 required /> 
			</label>
			
			<label for="field20"><span>Needed Date </span>
				<input type="text" class="input-field-60" name="needed_date_time" id="needed_date_time" value="${sales.needed_date_time}"  maxlength=14 size=40 /> 
			</label>
			
			<label for="field21"><span>From Account </span>
				<input type="text" class="input-field-60" name="from_account_id" id="from_account_id" value="${sales.from_account_id}"  maxlength=25 size=40 /> 
			</label>
			
			<label for="field22"><span>To Account </span>
				<input type="text" class="input-field-60" name="to_account_id" id="to_account_id" value="${sales.to_account_id}"  maxlength=25 size=40 /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field23"><span>Salesman ID </span>
				<select name="salesman_id" id="salesman_id" class="select-field-60" >
					<option value="" >Select one</option>
					<c:forEach items="${allSalesman}" var="as">
						<option value="${as.salesman_id}">${as.salesman_id}</option>
					</c:forEach>
				</select> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field23"><span>Salesman ID </span>
				<select name="salesman_id" id="salesman_id" class="select-field-60" >
					<c:forEach items="${allSalesman}" var="as">
						<option value="${as.salesman_id}" ${as.salesman_id == selectedSalesmanId ? 'selected="selected"' : ''}>${as.salesman_id}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<%-- <label for="field24"><span>Order Status <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="order_status" id="order_status" value="${sales.order_status}"  maxlength=1 size=40 required /> 
			</label> --%>
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field24"><span>Order Status </span>
				<select name="order_status" id="order_status" class="select-field-60" >
					<option value="A">Approved</option>
				</select> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field24"><span>Order Status </span>
				<select name="order_status" id="order_status" class="select-field-60" >
					<option value="" >Select one</option>
					<option value="P" ${sales.order_status == 'P' ? 'selected="selected"' : ''}>Pending</option>
					<option value="A" ${sales.order_status == 'A' ? 'selected="selected"' : ''}>Approved</option>
					<option value="C" ${sales.order_status == 'C' ? 'selected="selected"' : ''}>Cancel</option>
					<option value="S" ${sales.order_status == 'S' ? 'selected="selected"' : ''}>Success</option>
				</select> 
			</label>
			<%
			}
			%>
			
			<%-- <label for="field25"><span>Delivery Status <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="delivery_status" id="delivery_status" value="${sales.delivery_status}"  maxlength=1 size=40 required /> 
			</label> --%>
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field25"><span>Delivery Status </span>
				<select name="delivery_status" id="delivery_status" class="select-field-60" >
					<option value="P">Pending</option>
				</select> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field25"><span>Delivery Status </span>
				<select name="delivery_status" id="delivery_status" class="select-field-60" >
					<option value="" >Select one</option>
					<option value="P" ${sales.delivery_status == 'P' ? 'selected="selected"' : ''}>Pending</option>
					<option value="D" ${sales.delivery_status == 'D' ? 'selected="selected"' : ''}>Delivered</option>
					<option value="S" ${sales.delivery_status == 'S' ? 'selected="selected"' : ''}>Success</option>
					<option value="C" ${sales.delivery_status == 'C' ? 'selected="selected"' : ''}>Cancel</option>
				</select> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field126"><span>Created <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="created" id="created" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field126"><span>Created <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="created" id="created" value="${sales.created}"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field127"><span>Updated </span>
				<input type="text" class="input-field-60" readonly="readonly" name="updated" id="updated" value="${sales.updated}"  maxlength=14 size=40 /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field127"><span>Updated <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="updated" id="updated" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<label for="field28"><span>Created By </span>
				<input type="text" class="input-field-60" name="created_by" id="created_by" value="${sales.created_by}"  maxlength=40 size=40 /> 
			</label>
			
			</div>
			
			<div class="square-44">
			
			<label for="field29"><span>Updated By </span>
				<input type="text" class="input-field-60" name="updated_by" id="updated_by" value="${sales.updated_by}"  maxlength=40 size=40 /> 
			</label>
			
			</div>
			<br><br>
			<label><span></span>
					<input type="submit" value="Submit" />

					<a Class ="button" href="${pageContext.request.contextPath}/jsp/order/sales.jsp">Return</a>
			</label>
			
	</form>
	</div>
		</div>	
	</div><!-- mcontent -->
	
</div><!-- main -->
</body>
</html>
<br>
<div>