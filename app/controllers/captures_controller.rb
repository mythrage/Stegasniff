class CapturesController < ApplicationController
  # GET /captures
  # GET /captures.xml
  def index
    @captures = Capture.find(:all)

    respond_to do |format|
      format.html # index.html.erb
      format.xml  { render :xml => @captures }
    end
  end

  # GET /captures/1
  # GET /captures/1.xml
  def show
    @capture = Capture.find(params[:id])

    respond_to do |format|
      format.html # show.html.erb
      format.xml  { render :xml => @capture }
    end
  end

  # GET /captures/new
  # GET /captures/new.xml
  def new
    @capture = Capture.new

    respond_to do |format|
      format.html # new.html.erb
      format.xml  { render :xml => @capture }
    end
  end

  # GET /captures/1/edit
  def edit
    @capture = Capture.find(params[:id])
  end

  # POST /captures
  # POST /captures.xml
  def create
    @capture = Capture.new(params[:capture])

    respond_to do |format|
      if @capture.save
        flash[:notice] = 'Capture was successfully created.'
        format.html { redirect_to(@capture) }
        format.xml  { render :xml => @capture, :status => :created, :location => @capture }
      else
        format.html { render :action => "new" }
        format.xml  { render :xml => @capture.errors, :status => :unprocessable_entity }
      end
    end
  end

  # PUT /captures/1
  # PUT /captures/1.xml
  def update
    @capture = Capture.find(params[:id])

    respond_to do |format|
      if @capture.update_attributes(params[:capture])
        flash[:notice] = 'Capture was successfully updated.'
        format.html { redirect_to(@capture) }
        format.xml  { head :ok }
      else
        format.html { render :action => "edit" }
        format.xml  { render :xml => @capture.errors, :status => :unprocessable_entity }
      end
    end
  end

  # DELETE /captures/1
  # DELETE /captures/1.xml
  def destroy
    @capture = Capture.find(params[:id])
    @capture.destroy

    respond_to do |format|
      format.html { redirect_to(captures_url) }
      format.xml  { head :ok }
    end
  end
end
