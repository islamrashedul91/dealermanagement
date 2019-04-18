<jsp:include page="../../base.jsp"></jsp:include>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet"
	href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/copytest.css" />
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/table.css" />

<script type="text/javascript"
	src="${pageContext.request.contextPath}/js/jquery.min.js"></script>
<script type="text/javascript"
	src="${pageContext.request.contextPath}/js/dataTables/jquery.dataTables.min.js"></script>
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/jquery.dataTables.min.css">

		<div class="mcontent">
			<div class="titlenav">
				<ul>
					<li class="title"><a href="">Purchase Enquiry</a></li>
					<li class="bread"><a href="">Dashboard > Order
							Management > Purchase List > Purchase Enquiry</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	
	<form action="" method="post">
		<table id="example" class="display" style="width: 100%" cellspacing="10">			
			<tr>
				<td Class ="FormCellColor" colspan="2">Purchase ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.purchase_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Purchase Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.purchase_type}" /></td>
				<td Class ="FormCellColor" colspan="2">Requisition ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.requisition_id}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Product ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.product_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Product Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.product_name}" /></td>
				<td Class ="FormCellColor" colspan="2">Pack Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.pack_type}" /></td>		
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Pack Size</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.pack_size}" /></td>
				<td Class ="FormCellColor" colspan="2">Pieces</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.piceces}" /></td>
				<td Class ="FormCellColor" colspan="2">Bonus ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.bonus_id}" /></td>
			</tr>
			
			<tr>			
				<td Class ="FormCellColor" colspan="2">Bonus Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.bonus_name}" /></td>
				<td Class ="FormCellColor" colspan="2">Order Pack</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.order_pack}" /></td>
				<td Class ="FormCellColor" colspan="2">Order Quantity</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.order_quantity}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Rate Per Pieces BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.rate_per_piceces}" /></td>
				<td Class ="FormCellColor" colspan="2">Rate Per Box BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.rate_per_box}" /></td>
				<td Class ="FormCellColor" colspan="2">TP Price BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.tp_price}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Total TP Price BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.total_tp_price}" /></td>
				<td Class ="FormCellColor" colspan="2">Discount Amount BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.discount_amt}" /></td>
				<td Class ="FormCellColor" colspan="2">Total Amount BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.total_amount}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Needed Date</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.needed_date_time}" /></td>			
				<td Class ="FormCellColor" colspan="2">From Account</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.from_account_id}" /></td>
				<td Class ="FormCellColor" colspan="2">To Account</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.to_account_id}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Order Status</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.order_status == 'P' ? 'Pending' : purchase.order_status == 'A' ? 'Approved' : purchase.order_status == 'C' ? 'Cancel' : purchase.order_status == 'S' ? 'Success' : ''}" /></td>
				<td Class ="FormCellColor" colspan="2">Delivery Status</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.delivery_status == 'P' ? 'Pending' : purchase.delivery_status == 'D' ? 'Received' : purchase.delivery_status == 'C' ? 'Cancel' : purchase.delivery_status == 'R' ? 'Return' : ''}" /></td>
				<td Class ="FormCellColor" colspan="2">Created</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.created}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Updated</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.updated}" /></td>
				<td Class ="FormCellColor" colspan="2">Created By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.created_by}" /></td>
				<td Class ="FormCellColor" colspan="2">Updated By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${purchase.updated_by}" /></td>
			</tr>
		</table>
		<br>
		
		<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399><br>
						<a Class ="button" href="${pageContext.request.contextPath}/jsp/order/purchase.jsp">Return</a>
					</td>
				</tr>
		</table>
	</form>
	</div>
</div><!-- mcontent -->
	
</div><!-- main -->

	<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->

</body>
</html>