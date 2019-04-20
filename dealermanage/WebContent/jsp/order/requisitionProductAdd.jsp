<jsp:include page="../../base.jsp"></jsp:include>
<br>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
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
	
	//document.getElementById('total_mrp_price').value = quantityMultiplyMrp;
	document.getElementById('total_mrp_price').value = quantityMultiplyMrp.toFixed(2);

}

function discountToTotalAmount() {
	
	var discount = document.getElementById('discount_amt').value;
	var totalMrp = document.getElementById('total_mrp_price').value;
	var totalMrpMinusDiscount = totalMrp - discount;
	
	//document.getElementById('total_amount').value = totalMrpMinusDiscount;
	document.getElementById('total_amount').value = totalMrpMinusDiscount.toFixed(2);

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
						<td class="PageHeader">Requisition Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Requisition Update</td>
					<%
					}
					%>
					</a></li>
					<li class="bread"><a href="">Dashboard > Order Management > Requisition List > <%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Requisition Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Requisition Update</td>
					<%
					}
					%></a></li>
				</ul>
			</div>
			<br>
<div class="card">
	<table class="display" style="width: 100%" cellspacing="10">			
		<tr>
			<td Class ="FormCellColor">Requisition ID</td>
			<td Class ="FormInputColor" colspan="2"><c:out value="${requisition_multi_id}" /></td>
			<td Class ="FormCellColor">DateTime</td>
			<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${strDateTimeMulti}" /></td> --%>
			<td Class ="FormInputColor" colspan="2">
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${strDateTimeMulti}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
			</td>
			<td Class ="FormCellColor">Customer Name</td>
			<td Class ="FormInputColor" colspan="2"><c:out value="${customerNameMulti}" /></td>
			<td Class ="FormCellColor">Mobile</td>
			<td Class ="FormInputColor" colspan="2"><c:out value="${customerMobileMulti}" /></td>
		</tr>
	</table>
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

	<form action="RequisitionProductController" method="post" name="frmSave">
		<div class="form-style-2-heading">Provide your information </div>
			<div class="square-44">
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field1"><span>Product Requisition ID <span class="required">*</span></span>
				<!-- generated auto increment id during add [S] -->
				<input type="text" class="input-field-60" readonly="readonly" name="requisition_product_id" id="requisition_product_id" value="${requisitionProductId}"  maxlength=25 size=40 required />
				<!-- generated auto increment id during add [E] --> 
			</label> 
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field1"><span>Product Requisition ID <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="requisition_product_id" id="requisition_product_id" value="${requisitionProduct.requisition_product_id}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field1"><span>Requisition ID <span class="required">*</span></span>
				<!-- generated auto increment id during add [S] -->
				<input type="text" class="input-field-60" readonly="readonly" name="requisition_id" id="requisition_id" value="${requisition_multi_id}"  maxlength=25 size=40 required />
				<!-- generated auto increment id during add [E] --> 
			</label> 
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field1"><span>Requisition ID <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="requisition_id" id="requisition_id" value="${requisitionProduct.requisition_id}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field2"><span>DateTime <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${strDateTimeMulti}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="date_time" id="date_time" value="${strDateTimeMulti}"  maxlength=14 size=40 required /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field2"><span>DateTime <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${requisitionProduct.date_time}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="date_time" id="date_time" value="${requisitionProduct.date_time}"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field4"><span>Product ID </span>
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
			<label for="field4"><span>Product ID </span>
				<select name="product_id" id="product_id" class="select-field-60" onchange="productChng();" >
					<c:forEach items="${allProduct}" var="ap">
						<option value="${ap.product_id}" ${ap.product_id == selectedProductId ? 'selected="selected"' : ''}>${ap.product_name}  -  ${ap.product_name}  -  ${ap.pack_type}  -  ${ap.pack_size}  -  ${ap.piceces}  -  ${ap.mrp_price}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<label for="field5"><span>Product Name <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="product_name" id="product_name" value="${requisitionProduct.product_name}"  maxlength=100 size=40 required /> 
			</label>
			
			<label for="field6"><span>Pack Type <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="pack_type" id="pack_type" value="${requisitionProduct.pack_type}"  maxlength=40 size=40 required /> 
			</label>
			
			<label for="field7"><span>Pack Size <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="pack_size" id="pack_size" value="${requisitionProduct.pack_size}"  maxlength=25 size=40 required /> 
			</label>
			
			<label for="field8"><span>Pieces <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="piceces" id="piceces" value="${requisitionProduct.piceces}"  maxlength=10 size=40 required /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field9"><span>Bonus ID </span>
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
			<label for="field9"><span>Bonus ID </span>
				<select name="bonus_id" id="bonus_id" class="select-field-60" onchange="bonusChng();" >
					<c:forEach items="${allBonus}" var="ab">
						<option value="${ab.bonus_id}" ${ab.bonus_id == selectedBonusId ? 'selected="selected"' : ''}>${ab.bonus_id}  -  ${ab.bonus_name}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<label for="field10"><span>Bonus Name </span>
				<input type="text" class="input-field-60" readonly="readonly" name="bonus_name" id="bonus_name" value="${requisitionProduct.bonus_name}"  maxlength=40 size=40 /> 
			</label>
			
			</div>
			
			&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
			
			<div class="square-44">
			
			<label for="field11"><span>Order Pack </span>
				<input type="text" class="input-field-60" name="order_pack" id="order_pack" value="${requisitionProduct.order_pack}"  maxlength=40 size=40 /> 
			</label>
			
			<label for="field12"><span>Order Quantity <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="order_quantity" id="order_quantity" value="${requisitionProduct.order_quantity}" onchange="quantityToTotalMRP(); discountToTotalAmount();" maxlength=10 size=40 required /> 
			</label>
			
			<label for="field13"><span>MRP <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="mrp_price" id="mrp_price" value="${requisitionProduct.mrp_price}" maxlength=10 size=40 required /> 
			</label>
			
			<label for="field14"><span>Total MRP BDT.<span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="total_mrp_price" id="total_mrp_price" value="${requisitionProduct.total_mrp_price}" maxlength=10 size=40 required /> 
			</label>
			
			<label for="field15"><span>Discount Amount <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="discount_amt" id="discount_amt" value="${requisitionProduct.discount_amt}" onchange="discountToTotalAmount();" maxlength=10 size=40 required /> 
			</label>
			
			<label for="field16"><span>Total Amount BDT. <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="total_amount" id="total_amount" value="${requisitionProduct.total_amount}"  maxlength=10 size=40 required /> 
			</label>
			
			<%-- <label for="field22"><span>Order Status <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="order_status" id="order_status" value="${requisition.order_status}"  maxlength=1 size=40 required /> 
			</label> --%>
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field17"><span>Order Status </span>
				<select name="order_status" id="order_status" class="select-field-60" >
					<option value="P">Pending</option>
				</select> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field17"><span>Order Status </span>
				<select name="order_status" id="order_status" class="select-field-60" >
					<option value="" >Select one</option>
					<option value="P" ${requisitionProduct.order_status == 'P' ? 'selected="selected"' : ''}>Pending</option>
					<option value="A" ${requisitionProduct.order_status == 'A' ? 'selected="selected"' : ''}>Approved</option>
					<option value="C" ${requisitionProduct.order_status == 'C' ? 'selected="selected"' : ''}>Cancel</option>
					<option value="S" ${requisitionProduct.order_status == 'S' ? 'selected="selected"' : ''}>Success</option>
				</select> 
			</label>
			<%
			}
			%>
			
			<%-- <label for="field18"><span>Delivery Status <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="delivery_status" id="delivery_status" value="${requisition.delivery_status}"  maxlength=1 size=40 required /> 
			</label> --%>
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field18"><span>Delivery Status </span>
				<select name="delivery_status" id="delivery_status" class="select-field-60" >
					<option value="P">Pending</option>
				</select> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field18"><span>Delivery Status </span>
				<select name="delivery_status" id="delivery_status" class="select-field-60" >
					<option value="" >Select one</option>
					<option value="P" ${requisitionProduct.delivery_status == 'P' ? 'selected="selected"' : ''}>Pending</option>
					<option value="D" ${requisitionProduct.delivery_status == 'D' ? 'selected="selected"' : ''}>Delivered</option>
					<option value="S" ${requisitionProduct.delivery_status == 'S' ? 'selected="selected"' : ''}>Success</option>
					<option value="C" ${requisitionProduct.delivery_status == 'C' ? 'selected="selected"' : ''}>Cancel</option>
				</select> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field19"><span>Created <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="<%=strDate%>" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="created" id="created" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field19"><span>Created <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${requisitionProduct.created}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="created" id="created" value="${requisitionProduct.created}"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field20"><span>Updated </span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${requisitionProduct.updated}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="updated" id="updated" value="${requisitionProduct.updated}"  maxlength=14 size=40 /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field20"><span>Updated <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="<%=strDate%>" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="updated" id="updated" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			</div>
			<br><br>
			<label><span></span>
					<input type="submit" value="Submit" />

					<%-- <a Class ="button" href="${pageContext.request.contextPath}/jsp/order/requisitionProductList.jsp">Return</a> --%>
					<a Class ="button" href="${pageContext.request.contextPath}/RequisitionMultiController?action=return&requisition_id=${requisition_multi_id}&date_time=${strDateTimeMulti}&customer_name=${customerNameMulti}&mobile=${customerMobileMulti}">Return</a></td>
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