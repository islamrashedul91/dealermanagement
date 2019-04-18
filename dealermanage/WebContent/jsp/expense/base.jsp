<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<!-- <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css"> -->
<link rel="stylesheet"
	href="https://use.fontawesome.com/releases/v5.6.3/css/all.css">
<link rel="stylesheet" href="../../css/copytest.css" />
<link rel="stylesheet" href="../../css/super-panel.css" />
<link href="../../css/page.css" rel="stylesheet" />
<script src="../../js/super-panel.js"></script>
<link href="../../css/accordion-menu.css" rel="stylesheet" />
<script src="../../js/accordion-menu.js"></script>
<style>
</style>
</head>
<body>
	<div class="sidenav">
		<div class="brand">
			<ul>
				<!-- <li><a href="#"><img class="brand-logo"
						src="images/ic-wallet-merchant.png" alt="Bulma Admin Template logo"></a></li> -->
				<!-- <li><a href="#"><img class="brand-logo"
						src="images/nccblogo.png" alt="Bulma Admin Template logo"></a></li> -->
			</ul>
		</div>
		<div id="panel1">
			
			<div class="menu">
			
				<a href="${pageContext.request.contextPath}/base.jsp"><i class="fas fa-tachometer-alt"></i>&nbsp;Dashboard</a>
				
				<button class="dropdown-btn">
					<span>&nbsp;Owner Management</span> <i class="fa fa-caret-down"></i>
				</button>
				<div class="dropdown-container">
					<a id="submenu" href="${pageContext.request.contextPath}/jsp/owner/ownerInfo.jsp">&nbsp;Owner Information</a>
				</div>
				
				<button class="dropdown-btn">
					<span>&nbsp;Account Management</span> <i class="fa fa-caret-down"></i>
				</button>
				<div class="dropdown-container">
					<a id="submenu" href="${pageContext.request.contextPath}/jsp/account/account.jsp">&nbsp;Account Information</a>
					<a id="submenu" href="${pageContext.request.contextPath}/jsp/account/dayWiseAccountBalance.jsp">&nbsp;Day Wise Account Balance</a>
					<a id="submenu" href="${pageContext.request.contextPath}/jsp/account/profitLoss.jsp">&nbsp;Profit Loss Infomation</a>
				</div>
				
				<button class="dropdown-btn">
					<span>&nbsp;Product Management</span> <i class="fa fa-caret-down"></i>
				</button>
				<div class="dropdown-container">
					<a id="submenu" href="${pageContext.request.contextPath}/jsp/product/productCategory.jsp">&nbsp;Product Category</a>
					<a id="submenu" href="${pageContext.request.contextPath}/jsp/product/generic.jsp">&nbsp;Generic</a>
					<a id="submenu" href="${pageContext.request.contextPath}/jsp/product/packPiceces.jsp">&nbsp;Pack Pieces</a>
					<a id="submenu" href="${pageContext.request.contextPath}/jsp/product/productType.jsp">&nbsp;Product Type</a>
					<a id="submenu" href="${pageContext.request.contextPath}/jsp/product/brand.jsp">&nbsp;Brand</a>
					<a id="submenu" href="${pageContext.request.contextPath}/jsp/product/product.jsp">&nbsp;Product</a>
				</div>
				
				<button class="dropdown-btn">
					<span>&nbsp;Sales Management</span> <i class="fa fa-caret-down"></i>
				</button>
				<div class="dropdown-container">
					<a id="submenu" href="${pageContext.request.contextPath}/jsp/order/requisitionMulti.jsp">&nbsp;Multi Order</a>
					<a id="submenu" href="${pageContext.request.contextPath}/jsp/order/salesMain.jsp">&nbsp;Sales Main</a>
				</div>
				
				<button class="dropdown-btn">
					<span>&nbsp;Purchase Management</span> <i class="fa fa-caret-down"></i>
				</button>
				<div class="dropdown-container">
					<a id="submenu" href="${pageContext.request.contextPath}/jsp/order/purchaseMain.jsp">&nbsp;Purchase Main</a>
					<a id="submenu" href="${pageContext.request.contextPath}/jsp/order/transactionMain.jsp">&nbsp;Transaction Main</a>
				</div>
				
				<button class="dropdown-btn">
					<span>&nbsp;Customer Management</span> <i class="fa fa-caret-down"></i>
				</button>
				<div class="dropdown-container">
					<a id="submenu" href="${pageContext.request.contextPath}/jsp/customer/customerInfo.jsp">&nbsp;Customer Information</a>
					<a id="submenu" href="${pageContext.request.contextPath}/jsp/order/customerPurchaseMain.jsp">&nbsp;Customer Purchase Main</a>
					<a id="submenu" href="${pageContext.request.contextPath}/jsp/order/customerTransactionMain.jsp">&nbsp;Customer Transaction Main</a>
				</div>
				
				<button class="dropdown-btn">
					<span>&nbsp;Salesman Management</span> <i class="fa fa-caret-down"></i>
				</button>
				<div class="dropdown-container">
					<a id="submenu" href="${pageContext.request.contextPath}/jsp/salesman/salesmanInfo.jsp">&nbsp;Salesman Information</a>
				</div>
				
				<button class="dropdown-btn">
					<span>&nbsp;Expense Management</span> <i class="fa fa-caret-down"></i>
				</button>
				<div class="dropdown-container">
					<a id="submenu" href="${pageContext.request.contextPath}/jsp/expense/expenseCategory.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Expense Category</a>
					<a id="submenu" href="${pageContext.request.contextPath}/jsp/expense/expenseMain.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Expense Main</a>
				</div>
				
				<button class="dropdown-btn">
					<span>&nbsp;Company Management</span> <i class="fa fa-caret-down"></i>
				</button>
				<div class="dropdown-container">
					<a id="submenu" href="${pageContext.request.contextPath}/jsp/product/company.jsp">&nbsp;Company</a>
				</div>
			</div>
			
			<%-- <div id="accordion">
				<ul>
					<li><a href="${pageContext.request.contextPath}/load_modules.jsp"><i class="fas fa-tachometer-alt"></i>&nbsp;Dashboard</a></li>
					<li><a href="${pageContext.request.contextPath}/base.jsp"><i class="fas fa-tachometer-alt"></i>&nbsp;Dashboard</a></li>					
					<li><a href="${pageContext.request.contextPath}/index.jsp"><i class="fas fa-store-alt"></i>&nbsp;Merchant</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/merchant/merchantBranch.jsp"><i class="fab fa-font-awesome-flag"></i>&nbsp;Merchant Branch</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/merchant/merchantBranchAll.jsp"><i class="fab fa-font-awesome-flag"></i>&nbsp;All Branches</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/merchant/merchantTransactionByBranchID.jsp"><i class="fas fa-history"></i>&nbsp;Merchant Transactions</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/merchant/merchantTransactionByBranch.jsp"><i class="fas fa-history"></i>&nbsp;Merchant Transactions</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/merchant/settlement.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Merchant Receivable</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/owner/ownerInfo.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Owner Information</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/account/account.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Account Information</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/account/dayWiseAccountBalance.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Day Wise Account Balance</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/account/profitLoss.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Profit Loss Infomation</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/customer/customerInfo.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Customer Information</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/product/productCategory.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Product Category</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/product/generic.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Generic</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/product/brand.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Brand</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/product/packPiceces.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Pack Pieces</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/product/product.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Product</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/product/productType.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Product Type</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/product/company.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Company</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/order/requisition.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Order</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/order/requisitionMulti.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Multi Order</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/order/sales.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Sales</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/order/salesMain.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Sales Main</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/order/customerPurchase.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Customer Purchase</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/order/customerPurchaseMain.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Customer Purchase Main</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/order/customerTransaction.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Customer Transaction</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/order/customerTransactionMain.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Customer Transaction Main</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/salesman/salesmanInfo.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Salesman Information</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/order/purchase.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Purchase Information</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/order/purchaseMain.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Purchase Main</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/order/transaction.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Transaction Information</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/order/transactionMain.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Transaction Main</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/expense/expenseCategory.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Expense Category</a></li>
					<li><a href="${pageContext.request.contextPath}/jsp/expense/expenseMain.jsp"><i class="far fa-money-bill-alt"></i>&nbsp;Expense Main</a></li>
				</ul>
			</div> --%>
		</div>
		<!-- <div class="menu">
			<a href="#"><span><i class="fa fa-dashboard"></i>&nbsp;Dashboard</span></a>
			<button class="dropdown-btn">
				<span><i class="fa fa-shopping-cart"></i>&nbsp;Merchant
					Management</span> <i class="fa fa-caret-down"></i>
			</button>
			<div class="dropdown-container">
				<a id="submenu" href="#">Merchant Listing</a>
			</div>
			<button class="dropdown-btn">
				<span><i class="fa fa-user-o"></i>&nbsp;User Profile</span> <i
					class="fa fa-caret-down"></i>
			</button>
			<div class="dropdown-container">
				<a id="submenu" href="#">Manage User</a> <a id="submenu" href="#">Role
					Setting</a> <a id="submenu" href="#">Permission Setting</a>
			</div>
			<a href="#"><span><i class="fa fa-cogs"></i>&nbsp;Parameter</span></a>
		</div> -->
	</div>
	<div class="main">
		<div class="rightnav">
			<ul>
				<li class="dropdown"><a href="javascript:void(0)"
					class="dropbtn"><span class="merchant-user">
									<c:forEach items="${merchantBranchs}" var="mb">
										<c:out value="${mb.merchant_branch_name}" />
									</c:forEach>&nbsp;<i
							class="fa fa-angle-down"></i></span></a>
					<div class="dropdown-content">
						<!-- <a href="#"><span><i class="fa fa-user"></i>&nbsp;&nbsp;Profile</span></a> -->
						<a href="${pageContext.request.contextPath}/MerchantBranchController?action=enquiry&merchant_branch_id=${username}"><span><i class="fa fa-user"></i>&nbsp;&nbsp;Profile</span></a>
						<a href="${pageContext.request.contextPath}/passwordChange.jsp"><span><i class="fa fa-lock"></i>&nbsp;&nbsp;Password</span></a>
						<a href="${pageContext.request.contextPath}/logout.jsp"><span><i class="fa fa-power-off"></i>&nbsp;&nbsp;Logout</span></a>
					</div></li>
			</ul>
		</div>
		
		<script>
		/* Loop through all dropdown buttons to toggle between hiding and showing its dropdown content - This allows the user to have multiple dropdowns without any conflict */
		var dropdown = document.getElementsByClassName("dropdown-btn");
		var i;
		for (i = 0; i < dropdown.length; i++) {
			dropdown[i].addEventListener("click", function() {
				this.classList.toggle("active");
				var dropdownContent = this.nextElementSibling;
				if (dropdownContent.style.display === "block") {
					dropdownContent.style.display = "none";
				} else {
					dropdownContent.style.display = "block";
				}
			});
		}
	</script>